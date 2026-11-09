//! The work brief: what a worker reads before an attempt (ADR-0065).
//!
//! The text is rendered from stored rows. Every field passes the strip set again, so a row that
//! predates a stricter rule cannot reach a worker with a hostile character. Entries are ranked
//! pitfalls first, then open improvements, and the lowest-ranked entries are dropped first when
//! the text would pass [`BRIEF_TOKEN_BUDGET`].

use fleet_core::text::strip_keeping_lines;
use fleet_proto::v1::{GetWorkBriefReply, GetWorkBriefRequest};
use sqlx::Row;
use std::fmt::Write as _;

use super::{WorkFault, find_project, item_key, project_name};
use crate::store::{Store, StoreError};

/// Tokens a brief may take. Estimated at [`BYTES_PER_TOKEN`] bytes each.
pub const BRIEF_TOKEN_BUDGET: usize = 2000;
/// Bytes counted as one token. A cautious estimate for English and code.
pub const BYTES_PER_TOKEN: usize = 4;
/// Most pitfalls and most improvements the brief reads from the store, each.
pub const MAX_BRIEF_CANDIDATES: i64 = 200;
const ENTRY_TEXT_CHARS: usize = 300;
const ITEM_BODY_CHARS: usize = 1500;
const NOTICE_RESERVE_BYTES: usize = 64;

const BRIEF_ITEM: &str = "SELECT id, title, body FROM work_item WHERE project_id = $1 AND key = $2";

const BRIEF_SLICES: &str = "\
SELECT s.name FROM work_item_slice m \
JOIN work_slice s ON s.id = m.slice_id AND s.project_id = m.project_id \
WHERE m.project_id = $1 AND m.item_id = $2 ORDER BY s.name";

const BRIEF_PITFALLS: &str = "\
SELECT symptom, cause, fix, count(*) OVER () AS total FROM pitfall \
WHERE user_id = $1 AND (project_id IS NULL OR project_id = $2) \
ORDER BY hits DESC, last_hit_at DESC NULLS LAST, id DESC LIMIT $3";

const BRIEF_IMPROVEMENTS: &str = "\
SELECT title, body, occurrences, count(*) OVER () AS total FROM improvement \
WHERE project_id = $1 AND (disposition IS NULL OR disposition = 'accepted') \
AND (item_id = $2 OR vertical = ANY($3)) \
ORDER BY occurrences DESC, id LIMIT $4";

fn one_line(text: &str, max: usize) -> String {
    let flat = strip_keeping_lines(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    flat.chars().take(max).collect()
}

fn unseen_of(total: i64, read: usize) -> usize {
    usize::try_from(total).unwrap_or(0).saturating_sub(read)
}

fn cut(text: &str, max: usize) -> &str {
    let end = (0..=max.min(text.len()))
        .rev()
        .find(|&i| text.is_char_boundary(i))
        .unwrap_or(0);
    &text[..end]
}

/// Joins `head` and `entries` into text of at most `budget_tokens * BYTES_PER_TOKEN` bytes.
///
/// `head` is cut to the budget if it alone passes it. Entries are kept in order while they fit.
/// When some do not, the kept prefix leaves room for a notice line, and the returned count is
/// the number of entries not shown plus `unseen`, the entries the caller never read.
pub(super) fn render(
    head: &str,
    entries: &[String],
    unseen: usize,
    budget_tokens: usize,
) -> (String, usize) {
    let budget = budget_tokens.saturating_mul(BYTES_PER_TOKEN);
    let mut text = cut(head, budget).to_owned();
    let all: usize = entries.iter().map(String::len).sum();
    let fits = unseen == 0 && text.len().saturating_add(all) <= budget;
    let room = if fits {
        budget
    } else {
        budget.saturating_sub(NOTICE_RESERVE_BYTES)
    };
    if !fits {
        let end = cut(&text, room).len();
        text.truncate(end);
    }
    let mut shown = 0;
    for entry in entries {
        if text.len() + entry.len() > room {
            break;
        }
        text.push_str(entry);
        shown += 1;
    }
    let dropped = entries.len() - shown + unseen;
    if dropped > 0 {
        let _ = writeln!(text, "\n[{dropped} lower-ranked entries dropped]");
    }
    (text, dropped)
}

impl Store {
    /// Renders the brief of one item: its slices, the caller's pitfalls and the open
    /// improvements of the item or of its slices as verticals, within [`BRIEF_TOKEN_BUDGET`].
    ///
    /// # Errors
    ///
    /// [`WorkFault::ProjectNotFound`] and [`WorkFault::ItemNotFound`].
    pub async fn get_work_brief(
        &self,
        user_id: i64,
        request: &GetWorkBriefRequest,
    ) -> Result<GetWorkBriefReply, StoreError> {
        self.work_brief_within(user_id, request, BRIEF_TOKEN_BUDGET)
            .await
    }

    pub(super) async fn work_brief_within(
        &self,
        user_id: i64,
        request: &GetWorkBriefRequest,
        budget_tokens: usize,
    ) -> Result<GetWorkBriefReply, StoreError> {
        project_name(&request.project)?;
        item_key(&request.item_key)?;
        let mut tx = self.begin_read().await?;
        let project_id = find_project(&mut tx, user_id, &request.project).await?;
        let item = sqlx::query(BRIEF_ITEM)
            .bind(project_id)
            .bind(&request.item_key)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(WorkFault::ItemNotFound)?;
        let item_id: i64 = item.try_get("id")?;
        let title: String = item.try_get("title")?;
        let body: String = item.try_get("body")?;
        let slices: Vec<String> = sqlx::query_scalar(BRIEF_SLICES)
            .bind(project_id)
            .bind(item_id)
            .fetch_all(&mut *tx)
            .await?;
        let pitfalls = sqlx::query(BRIEF_PITFALLS)
            .bind(user_id)
            .bind(project_id)
            .bind(MAX_BRIEF_CANDIDATES)
            .fetch_all(&mut *tx)
            .await?;
        let improvements = sqlx::query(BRIEF_IMPROVEMENTS)
            .bind(project_id)
            .bind(item_id)
            .bind(&slices)
            .bind(MAX_BRIEF_CANDIDATES)
            .fetch_all(&mut *tx)
            .await?;
        let mut entries = Vec::new();
        let mut unseen = 0_usize;
        if let Some(row) = pitfalls.first() {
            unseen += unseen_of(row.try_get("total")?, pitfalls.len());
        }
        if let Some(row) = improvements.first() {
            unseen += unseen_of(row.try_get("total")?, improvements.len());
        }
        for row in &pitfalls {
            let (symptom, cause, fix): (String, String, String) = (
                row.try_get("symptom")?,
                row.try_get("cause")?,
                row.try_get("fix")?,
            );
            entries.push(format!(
                "pitfall: {} | cause: {} | fix: {}\n",
                one_line(&symptom, ENTRY_TEXT_CHARS),
                one_line(&cause, ENTRY_TEXT_CHARS),
                one_line(&fix, ENTRY_TEXT_CHARS),
            ));
        }
        for row in &improvements {
            let (name, detail): (String, String) = (row.try_get("title")?, row.try_get("body")?);
            let count: i32 = row.try_get("occurrences")?;
            entries.push(format!(
                "improvement (x{count}): {} | {}\n",
                one_line(&name, ENTRY_TEXT_CHARS),
                one_line(&detail, ENTRY_TEXT_CHARS),
            ));
        }
        let head = format!(
            "work item {}: {}\nslices: {}\n{}\n",
            one_line(&request.item_key, ENTRY_TEXT_CHARS),
            one_line(&title, ENTRY_TEXT_CHARS),
            slices.join(", "),
            one_line(&body, ITEM_BODY_CHARS),
        );
        let (text, dropped) = render(&head, &entries, unseen, budget_tokens);
        Ok(GetWorkBriefReply {
            text,
            dropped: u32::try_from(dropped).unwrap_or(u32::MAX),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{BYTES_PER_TOKEN, render};

    fn entries(count: usize, each: usize) -> Vec<String> {
        vec!["x".repeat(each); count]
    }

    #[test]
    fn entries_filling_the_budget_exactly_drop_nothing() {
        let budget_tokens = 10;
        let budget = budget_tokens * BYTES_PER_TOKEN;
        let (text, dropped) = render("", &entries(4, budget / 4), 0, budget_tokens);
        assert_eq!(dropped, 0);
        assert_eq!(text.len(), budget);
    }

    #[test]
    fn one_byte_over_the_budget_drops_and_stays_within_it() {
        let budget_tokens = 100;
        let budget = budget_tokens * BYTES_PER_TOKEN;
        let (text, dropped) = render("", &entries(2, budget / 2 + 1), 0, budget_tokens);
        assert_eq!(dropped, 1);
        assert!(text.len() <= budget, "{} > {budget}", text.len());
        assert!(text.contains("[1 lower-ranked entries dropped]"));
    }

    #[test]
    fn a_head_filling_the_budget_leaves_room_for_the_notice() {
        let budget_tokens = 100;
        let budget = budget_tokens * BYTES_PER_TOKEN;
        let head = "\u{e9}".repeat(budget);
        let (text, dropped) = render(&head, &entries(2, 10), 0, budget_tokens);
        assert_eq!(dropped, 2);
        assert!(text.len() <= budget, "{} > {budget}", text.len());
        assert!(text.contains("[2 lower-ranked entries dropped]"));
    }

    #[test]
    fn unseen_entries_count_as_dropped() {
        let (text, dropped) = render("", &entries(1, 4), 7, 100);
        assert_eq!(dropped, 7);
        assert!(text.contains("[7 lower-ranked entries dropped]"));
    }
}
