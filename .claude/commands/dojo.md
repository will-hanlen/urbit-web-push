Send a command to the fake ~zod's dojo and return its output.

Takes one argument: the dojo command to run (e.g. `|commit %web-push`, `|rein %web-push [& %notifchat]`).

The fakezod should be running in a tmux session:window called `web-push:zod`.

## Steps

1. **Run command:** Execute `tmux-dojo` with the pier. Use 30s timeout for quick commands, 240s for long ones like `|commit`:
   ```
   tmux-dojo "web-push:zod" 30 "<COMMAND>"
   ```
   - stdout = dojo output (between command echo and final prompt)
   - stderr = OK or TIMEOUT
   - Exit 0 = prompt returned (inspect stdout for Hoon errors)
   - Exit 1 = timeout or couldn't get a clean prompt

2. **Report result:** Show the dojo output to the user. If the command timed out, report the timeout. Scan for common error strings: `ford: %error`, `nest-fail`, `mint-nice`, `-find.`, `mull-grow`, `fire-type`, `generator-build-fail`.
