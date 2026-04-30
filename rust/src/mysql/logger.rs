use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::mysql::mysql::MysqlTransaction;

fn log_mysql(tx: &MysqlTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("mysql")?;
    if let Some(ref greeting) = tx.greeting {
        js.set_uint("protocol_version", greeting.protocol_version as u64)?;
        js.set_string("server_version", &greeting.server_version)?;
    }
    js.close()?;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn SCMysqlLoggerLog(
    tx: *const std::os::raw::c_void, js: *mut std::os::raw::c_void,
) -> bool {
    let tx = cast_pointer!(tx, MysqlTransaction);
    let js = cast_pointer!(js, JsonBuilder);
    log_mysql(tx, js).is_ok()
}
