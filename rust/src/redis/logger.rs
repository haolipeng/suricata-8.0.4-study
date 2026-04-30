use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::redis::redis::RedisTransaction;

fn log_redis(tx: &RedisTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("redis")?;
    if let Some(ref name) = tx.software_name {
        js.set_string("software_name", name)?;
    }
    if let Some(ref ver) = tx.software_version {
        js.set_string("software_version", ver)?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCRedisLoggerLog(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, RedisTransaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_redis(tx, js).is_ok()
}
