# cradle-hooks

Contains the hooking logic in use by the cradle workspace (tools and plugins)

## Example

Hooking a function and continuing execution

```rust
use cradle_hooks::{HookAction, HookEngine};
use cradle_shared::CradleResult;
use windows_sys::Win32::Foundation::HANDLE;

fn install_hook(process_handle: HANDLE) -> CradleResult {
    let mut engine = HookEngine::new(process_handle);

    unsafe {
        engine.hook_export("foo.dll", "bar", Box::new(|ctx| {
            let arg = ctx.arg(0);
            let arg2 = ctx.arg(1);
            println!("hooked! arg = {arg}, arg2 = {arg2}");
            Ok(HookAction::Continue)
        }))
    }
}
```