Update the fake ~zod's mounted %web-push desk.

The fakezod should be running in a tmux session:window called `web-push:zod`.

The fakezod should have its %web-push desk mounted at `./zod/web-push`.

## Steps

1. **Update the pier's mounted %web-push desk**: rsync the source tree into the pier's mounted desk:
   ```
   rsync -aL . zod/web-push/ --exclude='.git' --exclude='.claude' --exclude='zod'
   ```

2. **Commit the desk:** Execute `tmux-dojo` with the pier:
   ```
   tmux-dojo "web-push:zod" 240 "|commit %web-push"
   ```
   - stdout = dojo output (between command echo and final prompt)
   - stderr = OK or TIMEOUT
   - Exit 0 = prompt returned (inspect stdout for Hoon errors)
   - Exit 1 = timeout or couldn't get a clean prompt

3. **Report result:** Show the dojo output to the user. If the command timed out, report the timeout. Scan for common error strings: `ford: %error`, `nest-fail`, `mint-nice`, `-find.`, `mull-grow`, `fire-type`, `generator-build-fail`.
If an error occurs it will often come with a line number corresponding to where the compilation or runtime error occurred.

You can double-check the result of a compilation by the dojo command `-build-file %/path/to/file/hoon`.
