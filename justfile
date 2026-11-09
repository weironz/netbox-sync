set windows-shell := ["powershell.exe", "-NoProfile", "-Command"]

default:
    @just --list

fmt:
    cargo fmt --all

check:
    cargo fmt --all -- --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked

test:
    cargo test --locked

build:
    cargo build --locked --release

snapshot url site token_file output:
    cargo run --locked -- snapshot --netbox-url "{{url}}" --site "{{site}}" --token-file "{{token_file}}" --output "{{output}}"

plan snapshot inventory output_dir:
    cargo run --locked -- plan --snapshot "{{snapshot}}" --inventory "{{inventory}}" --out-dir "{{output_dir}}"

plan-for netbox_site snapshot inventory output_dir:
    cargo run --locked -- plan --netbox-site "{{netbox_site}}" --snapshot "{{snapshot}}" --inventory "{{inventory}}" --out-dir "{{output_dir}}"

image tag="netbox-sync:local":
    docker build --platform linux/amd64 --tag "{{tag}}" .

release tag:
    gh workflow run release.yml --ref main -f tag="{{tag}}"

publish-images tag acr_namespace="willspace":
    gh workflow run publish-images.yml --ref main -f tag="{{tag}}" -f acr_namespace="{{acr_namespace}}"
