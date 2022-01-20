use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use structopt::StructOpt;
use walkdir::WalkDir;

#[derive(StructOpt, Debug)]
#[structopt(name = "ffp - Fast Finger Printing for Directories")]
struct Opt {
    #[structopt(name = "DIRECTORY", parse(from_os_str))]
    directory: PathBuf,

    #[structopt(short = "s", long = "buff-size", default_value = "8192")]
    buff_size: u64,

    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
}

fn get_fingerprint(file_name: &Path, buff_size: usize, is_verbose: bool) -> Vec<u8> {
    let mut buff = vec![0u8; buff_size];

    let mut file = File::open(file_name).unwrap();
    let n = file.read(buff.as_mut_slice()).unwrap();

    if is_verbose {
        println!("Read {} bytes.", n);
    }

    let mut sha256 = Sha256::new();
    sha256.update(buff);
    let file_digest = sha256.finalize();

    if is_verbose {
        println!("SHA256: {:02x}", file_digest);
    }

    return file_digest.to_vec();
}

fn main() {
    let args = Opt::from_args();

    let mut directory = args.directory.clone();

    assert!(directory.exists(), "Not found: {}", directory.display());

    let buff_size: usize = args.buff_size.try_into().unwrap();

    let mut counter = 0;
    let mut hash_list: Vec<Vec<u8>> = Vec::new();

    for fs_entry in WalkDir::new(&mut directory) {
        let dir_entry = fs_entry.unwrap();

        if args.verbose {
            println!("Scanning: {:?}", dir_entry.path());
        }

        let file_stats = dir_entry.metadata().unwrap();
        if file_stats.is_file() {
            if args.verbose {
                println!("Processing file:");
                println!("\tSize: {}", file_stats.len());
            }

            let file_fp = get_fingerprint(dir_entry.path(), buff_size, args.verbose);
            hash_list.push(file_fp);
            counter += 1;
        } else {
            if args.verbose {
                println!("Skipping directory: {}", dir_entry.path().display());
            }
        }
    }

    let hash_list_sorted: Vec<u8> = hash_list.into_iter().flatten().collect();

    let mut sha256 = Sha256::new();
    sha256.update(hash_list_sorted);
    let digest = sha256.finalize();
    println!("Directory:\t{}", directory.display());
    println!("File count:\t{}", counter);
    println!("SHA256:\t\t{:02x}", digest);
}
