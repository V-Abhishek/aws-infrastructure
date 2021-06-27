# AWS Infrastructure

### PROJECT DESCRIPTION

This repository contains code for building the entire Infrastructure required for hosting [Online Bookstore](https://github.com/V-Abhishek/online-bookstore) web application on AWS cloud platform. AWS resources like VPC, Subnets, S3 bucket, RDS, EC2, Auto Scaling, Elastic Load Balancer, etc. are provisioned using **Terraform**.

---

### INFRASTRUCTURE AS CODE

<img alt="IaaC" src="https://github.com/V-Abhishek/aws-infrastructure/blob/main/images/IaaC.png" />

---

### BUILD INFRASTRUCTURE

1. Clone this repository
2. Download terraform from the official site
3. Copy the terraform binary into your cloned folder or set it in your path
4. Open Terminal and enter `terraform plan`
5. Once the plan is verified, enter `terraform apply`
6. View your VPC on AWS VPC Console
7. Incase, you want tear down the infrastructure enter `terraform destroy`

---

### UPLOAD SSL

Following command uploads SSL certifcate of the website domain to AWS Certificate Manager (ACM)

```
sudo aws acm import-certificate --certificate fileb://prodcertificate.pem --certificate-chain fileb://prod_certificate_chain.pem --private-key fileb://privatekey.pem --profile prod
```