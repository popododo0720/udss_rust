use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: Option<String>,

    #[arg(short, long, default_value_t = 0)]
    count: i32,

    #[arg(short, long)]
    file: Option<String>,

    #[arg(short, long)]
    bind_interface: Option<String>,
}

fn main() {
    let args = Args::parse();
}
