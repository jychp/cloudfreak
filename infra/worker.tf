resource "cloudflare_workers_script" "worker" {
  account_id = var.cloudflare_account_id
  name       = "cf-scanner"
  content    = file("workers/v1.js")
  module     = true
}
