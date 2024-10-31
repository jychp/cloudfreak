resource "cloudflare_workers_script" "cf-scanner" {
  account_id = var.cloudflare_account_id
  name       = "cf-scanner"
  content    = file("workers/v1.js")
  module     = true

  secret_text_binding {
    name = "APIKEY"
    text = var.cf_scanner_apikey
  }
}
