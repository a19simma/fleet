# Fleet job

You run as an unattended fleet job in a git worktree on a prepared branch. Do the task in the prompt, then stop.

- Commit finished work on the current branch with a semantic message: `type(scope): subject`, imperative, lowercase, 72 characters or fewer.
- Add no attribution lines to commits or pull requests.
- Do not push and do not run `gh`. The daemon publishes the branch.
- Do not change git config.
