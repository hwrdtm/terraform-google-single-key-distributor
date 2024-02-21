locals {
  function_files = [
    "${path.module}/files/function/main.go",
    "${path.module}/files/function/go.mod",
  ]
  function_md5sums     = [for f in local.function_files : filemd5(f)]
  function_dirchecksum = md5(join("-", local.function_md5sums))
  project_ids          = toset(concat([var.project_id], var.project_ids))
}

// Bucket for storing the Cloud Function source code
resource "google_storage_bucket" "function_bucket" {
  project       = var.project_id
  name          = "${var.project_id}-function-${var.function_name}"
  location      = "US"
  force_destroy = true
}

// Archive the Cloud Function source code
data "archive_file" "function" {
  type        = "zip"
  source_dir  = "${path.module}/files/function"
  output_path = "${path.module}/files/build/${local.function_dirchecksum}.zip"
}

// Upload the Cloud Function source code to the bucket
resource "google_storage_bucket_object" "archive" {
  name   = data.archive_file.function.output_path
  bucket = google_storage_bucket.function_bucket.name
  source = data.archive_file.function.output_path
}

// Service Account for the Cloud Function
resource "google_service_account" "distributor" {
  project      = var.project_id
  account_id   = "key-distributor"
  display_name = "Cloud Function to generate and encrypt SA keys"
}

// Grant the Cloud Function the permission to create Service Account keys based on the organization ID
resource "google_organization_iam_member" "distributor" {
  count  = var.org_id != "" ? 1 : 0
  member = "serviceAccount:${google_service_account.distributor.email}"
  role   = "roles/iam.serviceAccountKeyAdmin"
  org_id = var.org_id
}

// Grant the Cloud Function the permission to create Service Account keys based on the project IDs
resource "google_project_iam_member" "distributor" {
  for_each = local.project_ids
  member   = "serviceAccount:${google_service_account.distributor.email}"
  role     = "roles/iam.serviceAccountKeyAdmin"
  project  = var.project_id
}

// Cloud Function that generates and encrypts a new Service Account key
resource "google_cloudfunctions_function" "function" {
  project      = var.project_id
  region       = var.region
  name         = var.function_name
  description  = "Generates and encrypts a new Service Account key given a GPG public key"
  runtime      = "go118"
  trigger_http = true

  service_account_email = google_service_account.distributor.email
  source_archive_bucket = google_storage_bucket.function_bucket.name
  source_archive_object = google_storage_bucket_object.archive.name
  entry_point           = "GenerateAndEncrypt"
  environment_variables = {
    PUBLIC_KEY                   = file(var.public_key_file)
    SERVICE_ACCOUNT_EMAIL_TARGET = var.service_account_email_target
  }
}

// Grant the Cloud Function invoker permission to invoke the Cloud Function
resource "google_cloudfunctions_function_iam_member" "invoker" {
  for_each       = toset(var.function_members)
  project        = var.project_id
  cloud_function = google_cloudfunctions_function.function.name
  region         = var.region
  role           = "roles/cloudfunctions.invoker"
  member         = each.value
}

// Local file to store the Cloud Function invoker script
resource "local_file" "invoker" {
  filename        = "get-key"
  file_permission = "0755"
  content = templatefile("${path.module}/templates/get-key.tpl", {
    project  = var.project_id
    region   = var.region
    function = var.function_name
  })
}