variable "region"{}
variable "vpc_cidr" {
  default = "10.0.0.0/16"
}
variable "rds_identifier" {}
variable "database_name" {}
variable "database_password" {}
variable "database_user" {}
variable "bucketname" {}
variable "deployment-bucket"{}
variable "lambda-bucket"{}
variable "ami_id" {}
variable "deployment_account_number" {}
variable "csye6225-webapp" {
  type = string
  default = "csye6225-webapp"
}
variable "ssh_keyname" {
  type = string 
}
variable "circleCI_username" {}
variable "dns-name" {}
variable "ssl_certificate_arn" {}