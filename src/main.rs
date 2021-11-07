use core::panic;
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

    #[structopt(short = "s", long = "size", default_value = "4096")]
    digest_size: u64,

    #[structopt(short = "H", long = "histogram")]
    histogram: bool,

    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
}

fn main() {
    let opt = Opt::from_args();

    assert!(
        opt.directory.exists(),
        "Not found: {}",
        opt.directory.display()
    );

    assert!(!opt.histogram, "Not implemented!");

    let buff_size: usize = match opt.digest_size.try_into() {
        Ok(val) => val,
        Err(err) => {
            println!("{}", err);
            4096
        }
    };

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

                            if meta.len() < 2 * opt.digest_size {
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
                                                let res = sha256.finalize();

                                                if opt.verbose {
                                                    println!("\tSHA256: {:02x}", res);
                                                }
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
                                                let res = sha256.finalize();

                                                if opt.verbose {
                                                    println!("\tSHA256: {:02x}", res);
                                                }
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
                                            meta.len() - (opt.digest_size as u64),
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
                                                        let res = sha256.finalize();

                                                        if opt.verbose {
                                                            println!("\tSHA256: {:02x}", res);
                                                        }
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
}
