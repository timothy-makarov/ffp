use core::panic;
use std::path::Path;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::prelude::*;
use std::io::Read;
use std::io::SeekFrom;
use std::path::PathBuf;
use structopt::StructOpt;
use walkdir::WalkDir;

#[derive(StructOpt, Debug)]
#[structopt(name = "ffp - Fast FingerPrinting")]
struct Opt {
    #[structopt(name = "DIRECTORY", parse(from_os_str))]
    directory: PathBuf,

    #[structopt(short = "s", long = "buff-size", default_value = "4096")]
    buff_size: u64,

    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
}

fn get_single_fingerprint(file_name: &Path, file_size: usize, opt: Opt) -> Option<Vec<u8>> {
    let mut buff = vec![0u8; file_size];
    match File::open(file_name) {
        Ok(mut file) => {
            match file.read(buff.as_mut_slice()) {
                Ok(n) => {
                    if opt.verbose {
                        println!("\tRead {} bytes.", n);
                    }

                    let mut sha256 = Sha256::new();
                    sha256.update(buff);
                    let file_digest = sha256.finalize();

                    if opt.verbose {
                        println!("\tSHA256: {:02x}", file_digest);
                    }

                    return Some(file_digest.to_vec());
                }
                Err(err) => {
                    println!("{}", err);
                    return None;
                }
            };
        }
        Err(err) => {
            println!("{}", err);
            return None;
        }
    };
}

fn get_double_fingerprint(file_name: &Path, file_size: usize, opt: Opt) -> Option<Vec<u8>> {
    let mut total = vec![0u8; 0];
    //
    // TODO: Continue the same way as above...
    //
}

fn main() {
    let opt = Opt::from_args();

    assert!(
        opt.directory.exists(),
        "Not found: {}",
        opt.directory.display()
    );

    let buff_size: usize = match opt.buff_size.try_into() {
        Ok(val) => val,
        Err(err) => {
            println!("{}", err);
            4096
        }
    };

    let mut counter = 0;
    let mut total = vec![0u8; 0];

    for entry in WalkDir::new(opt.directory) {
        match entry {
            Ok(entry) => {
                if opt.verbose {
                    println!("Scanning: {:?}", entry.path());
                }

                match entry.metadata() {
                    Ok(meta) => {
                        if meta.is_file() {
                            if opt.verbose {
                                println!("Processing file:");
                                println!("\tSize: {}", meta.len());
                            }

                            if meta.len() < 2 * opt.buff_size {
                                if opt.verbose {
                                    println!("\tSmall file.");
                                }

                                let buff_size = match meta.len().try_into() {
                                    Ok(val) => val,
                                    Err(err) => {
                                        panic!("{}", err);
                                    }
                                };

                                let mut buff = vec![0u8; buff_size];
                                match File::open(entry.path()) {
                                    Ok(mut file) => {
                                        match file.read(buff.as_mut_slice()) {
                                            Ok(n) => {
                                                if opt.verbose {
                                                    println!("\tRead {} bytes.", n);
                                                }

                                                let mut sha256 = Sha256::new();
                                                sha256.update(buff);
                                                let file_digest = sha256.finalize();

                                                if opt.verbose {
                                                    println!("\tSHA256: {:02x}", file_digest);
                                                }

                                                total.extend(file_digest);
                                                counter += 1;
                                            }
                                            Err(err) => {
                                                println!("{}", err);
                                                continue;
                                            }
                                        };
                                    }
                                    Err(err) => {
                                        println!("{}", err);
                                        continue;
                                    }
                                };
                            } else {
                                if opt.verbose {
                                    println!("\tFingerprinting the file's head.");
                                }

                                let mut buff_head = vec![0u8; buff_size];
                                match File::open(entry.path()) {
                                    Ok(mut file) => {
                                        match file.read(buff_head.as_mut_slice()) {
                                            Ok(n) => {
                                                if opt.verbose {
                                                    println!("\tRead {} bytes.", n);
                                                }

                                                let mut sha256 = Sha256::new();
                                                sha256.update(buff_head);
                                                let file_digest = sha256.finalize();

                                                if opt.verbose {
                                                    println!("\tSHA256: {:02x}", file_digest);
                                                }

                                                total.extend(file_digest);
                                            }
                                            Err(err) => {
                                                println!("{}", err);
                                                continue;
                                            }
                                        };
                                    }
                                    Err(err) => {
                                        println!("{}", err);
                                    }
                                }

                                if opt.verbose {
                                    println!("\tFingerprinting the file's tail.");
                                }

                                let mut buff_tail = vec![0u8; buff_size];
                                match File::open(entry.path()) {
                                    Ok(mut file) => {
                                        match file.seek(SeekFrom::Start(
                                            meta.len() - (opt.buff_size as u64),
                                        )) {
                                            Ok(p) => {
                                                if opt.verbose {
                                                    println!("\tMoved to {}", p);
                                                }

                                                match file.read(buff_tail.as_mut_slice()) {
                                                    Ok(n) => {
                                                        if opt.verbose {
                                                            println!("\tRead {} bytes.", n);
                                                        }

                                                        let mut sha256 = Sha256::new();
                                                        sha256.update(buff_tail);
                                                        let file_digest = sha256.finalize();

                                                        if opt.verbose {
                                                            println!(
                                                                "\tSHA256: {:02x}",
                                                                file_digest
                                                            );
                                                        }

                                                        total.extend(file_digest);
                                                        counter += 1;
                                                    }
                                                    Err(err) => {
                                                        println!("{}", err);
                                                        continue;
                                                    }
                                                };
                                            }
                                            Err(err) => {
                                                println!("{}", err);
                                                continue;
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        println!("{}", err);
                                        continue;
                                    }
                                }
                            }
                        } else {
                            if opt.verbose {
                                println!("Skipping directory.");
                            }
                        }
                    }
                    Err(err) => {
                        println!("{}", err);
                    }
                }
            }
            Err(err) => {
                println!("{}", err);
            }
        }
    }

    let mut sha256 = Sha256::new();
    sha256.update(total);
    let digest = sha256.finalize();
    println!("SHA256: {:02x}", digest);
    println!("Total files: {}", counter);
}
