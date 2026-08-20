use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match parse_args().and_then(|args| {
        mvm_fs::extension_image::materialize_extension_image(
            &args.source,
            &args.entrypoint,
            &args.output,
        )
        .map_err(|error| error.to_string())
    }) {
        Ok(image) => {
            println!("{} {}", image.path.display(), image.size_bytes);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("mvm-extension-image: {error}");
            ExitCode::from(2)
        }
    }
}

struct Args {
    source: PathBuf,
    entrypoint: PathBuf,
    output: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut source = None;
    let mut entrypoint = None;
    let mut output = None;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {}", argument.to_string_lossy()))?;
        match argument.to_str() {
            Some("--source") if source.is_none() => source = Some(PathBuf::from(value)),
            Some("--entrypoint") if entrypoint.is_none() => entrypoint = Some(PathBuf::from(value)),
            Some("--output") if output.is_none() => output = Some(PathBuf::from(value)),
            _ => {
                return Err(format!(
                    "unknown or repeated argument {}",
                    argument.to_string_lossy()
                ));
            }
        }
    }
    Ok(Args {
        source: source.ok_or_else(|| "missing --source".to_string())?,
        entrypoint: entrypoint.ok_or_else(|| "missing --entrypoint".to_string())?,
        output: output.ok_or_else(|| "missing --output".to_string())?,
    })
}
