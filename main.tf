provider "aws" {
  region = "${var.region}"
}

#VPC
resource "aws_vpc" "csye6225_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  enable_classiclink_dns_support = true
  assign_generated_ipv6_cidr_block = false

  tags = {
    Name = "csye6225_vpc"
  }
}

#Internet Gateway
resource "aws_internet_gateway" "csye6225_gateway" {
  vpc_id = "${aws_vpc.csye6225_vpc.id}"

  tags = {
    Name = "csye6225_gateway"
  }
}

#Subnet
resource "aws_subnet" "csye6225_subnet" {
  count = "${length(data.aws_availability_zones.available_subnet.names)}"
  vpc_id = "${aws_vpc.csye6225_vpc.id}"
  cidr_block = "10.0.${length(data.aws_availability_zones.available_subnet.names) + count.index}.0/24"
  availability_zone = "${element(data.aws_availability_zones.available_subnet.names, count.index)}"

  tags = {
    Name = "public-${element(data.aws_availability_zones.available_subnet.names, count.index)}"
  }
}

#Route Table
resource "aws_route_table" "csye6225_route_table" {
  vpc_id = "${aws_vpc.csye6225_vpc.id}"
  tags = {
    Name = "csye6225_route_table"
  }
}
resource "aws_route" "route" {
  route_table_id                = "${aws_route_table.csye6225_route_table.id}"
  destination_cidr_block        = "0.0.0.0/0"
  gateway_id                    = "${aws_internet_gateway.csye6225_gateway.id}"

}
resource "aws_route_table_association" "table_association" {
  count                   = "${length(data.aws_availability_zones.available_subnet.names)}"  
  subnet_id               = "${element(aws_subnet.csye6225_subnet.*.id, count.index)}"
  route_table_id          = "${aws_route_table.csye6225_route_table.id}"
}

#EC2 Security Group for EC2 instance
resource "aws_security_group" "application" {
  name   = "application"
  vpc_id = "${aws_vpc.csye6225_vpc.id}"
  ingress {
    from_port  = 80
    to_port = 80
    protocol = "tcp"
    security_groups = ["${aws_security_group.lb-security-group.id}"]
  }
  # ingress {
  #   from_port  = 22
  #   to_port = 22
  #   protocol = "tcp"
  #   security_groups = ["${aws_security_group.lb-security-group.id}"]
  # }
  ingress {
    from_port  = 8080
    to_port = 8080
    protocol = "tcp"
    security_groups = ["${aws_security_group.lb-security-group.id}"]
    description = "tomcat"
  }
  ingress {
    from_port  = 443
    to_port = 443
    protocol = "tcp"
    security_groups = ["${aws_security_group.lb-security-group.id}"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#RDS instance
resource "aws_db_subnet_group" "rds_application" {
  name = "application"
  description = "RDS subnet group"
  subnet_ids  = "${aws_subnet.csye6225_subnet.*.id}"
  
  tags ={
    Name = "DB subnet group"
  }
}

#EC2 Security Group for RDS instance
resource "aws_security_group" "database" {
  name  = "database"
  description = "RDS MySQL server"
  vpc_id = "${aws_vpc.csye6225_vpc.id}"
  #Add ingress rules for port 3306
  ingress {
    from_port = 3306
    to_port = 3306
    protocol = "tcp"
    #cidr_blocks = ["0.0.0.0/0"]
    security_groups = ["${aws_security_group.application.id}"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#RDS MySQL database instance in VPC
resource "aws_db_instance" "database_instance" {
  identifier = "${var.rds_identifier}"
  allocated_storage = 20
  engine = "mysql"
  engine_version = "5.7.28"
  instance_class = "db.t3.micro"
  multi_az = false
  name = "${var.database_name}"
  username = "${var.database_user}"
  password = "${var.database_password}"
  db_subnet_group_name = "${aws_db_subnet_group.rds_application.id}"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  publicly_accessible = "false"
  skip_final_snapshot = true
  deletion_protection = false
  delete_automated_backups = true
  storage_encrypted = "true"
  parameter_group_name = "${aws_db_parameter_group.db_parameter_group.name}"
}
# DB parameter group 
resource "aws_db_parameter_group" "db_parameter_group" {
  name   = "db-parameter-group-ssl"
  family = "mysql5.7"

  parameter {
    name  = "performance_schema"
    value = "1"
    apply_method = "pending-reboot"
  }
}

#Private S3 bucket named as webapp-abhishek
resource "aws_s3_bucket" "webapp-abhishek" {
  bucket = "${var.bucketname}"
  acl    = "private"
  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  lifecycle_rule {
    enabled = true
    transition {
      days = 30
      storage_class = "STANDARD_IA"
    }
  }
}

#Public accessibility restricted
resource "aws_s3_bucket_public_access_block" "webapp-abhishek" {
  bucket = "${aws_s3_bucket.webapp-abhishek.id}"

  block_public_acls   = false
  ignore_public_acls = false
  block_public_policy = true
  restrict_public_buckets = true

  depends_on = [
    aws_s3_bucket_policy.webapp-abhishek
  ]
}

#Bucket Policy
resource "aws_s3_bucket_policy" "webapp-abhishek" {
  bucket = "${aws_s3_bucket.webapp-abhishek.id}"

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [ 
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": [
            "Account1",
            "Account2"
          ]
        },
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::${var.bucketname}",
          "arn:aws:s3:::${var.bucketname}/*"
        ]
      }
    ]
}
POLICY
}

#IAM Role
resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
      tag-key = "tag-value"
  }
}

#IAM instance profile
resource "aws_iam_instance_profile" "EC2-CSYE6225" {
  name = "EC2-CSYE6225"
  role = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
}

#Add IAM policy and giving access to S3 Image Bucket
resource "aws_iam_role_policy" "Access-S3-Images" {
  name = "Access-S3-Images"
  role = "${aws_iam_role.CodeDeployEC2ServiceRole.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "arn:aws:s3:::${var.bucketname}",
        "arn:aws:s3:::${var.bucketname}/*"
      ]
    }
  ]
}
EOF
}

#Add IAM policy document
data "aws_iam_policy_document" "iam_policy"{
  statement  {
    actions = ["s3:*"]
    effect= "Allow"
    resources = [
      "arn:aws:s3:::${var.bucketname}",
      "arn:aws:s3:::${var.bucketname}/*"
    ]
  }
}

#EC2 instance
# resource "aws_instance" "webapp" {
#   ami = "${var.ami_id}"
#   instance_type = "t2.micro"
#   key_name = "${var.ssh_keyname}"	
#   user_data = <<-EOF
#                 #!/bin/bash
#                 touch /home/ubuntu/configuaration.properties
#                 echo "dbName=${var.database_name}" >> /home/ubuntu/configuaration.properties
#                 echo "dbUserName=${var.database_user}" >> /home/ubuntu/configuaration.properties
#                 echo "dbPassword=${var.database_password}" >> /home/ubuntu/configuaration.properties
#                 echo "dbHostName=${aws_db_instance.database_instance.endpoint}" >> /home/ubuntu/configuaration.properties
#                 echo "bucketName=${var.bucketname}" >> /home/ubuntu/configuaration.properties
#                 EOF
#   tags = {
#     Name = "EC2 Instance"
#   }
#   vpc_security_group_ids = ["${aws_security_group.application.id}"]
#   subnet_id = aws_subnet.csye6225_subnet.*.id[1]
#   associate_public_ip_address = true
#   iam_instance_profile = "${aws_iam_instance_profile.EC2-CSYE6225.name}"
#   root_block_device {
#     volume_size = 20
#     volume_type = "gp2"
#   }
#   depends_on = [aws_db_instance.database_instance]
                
# }

#Dynamo Database
resource "aws_dynamodb_table" "db_table" {
    name = "csye6225"
    billing_mode = "PROVISIONED"
    read_capacity = 20
    write_capacity = 20
    hash_key = "id"
    attribute {
      name = "id"
      type = "S"
    }
}

#Deployment Bucket
resource "aws_s3_bucket" "deployment-bucket" {
  bucket = "${var.deployment-bucket}"
  acl    = "private"
  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  lifecycle_rule {
    enabled = true
    transition {
      days = 30
      storage_class = "STANDARD_IA"
    }
  }
}
#Access Deployment Bucket
resource "aws_s3_bucket_public_access_block" "deployment-bucket" {
  bucket = "${aws_s3_bucket.deployment-bucket.id}"

  block_public_acls   = false
  ignore_public_acls = false
  block_public_policy = true
  restrict_public_buckets = true

}

#IAM Policy to Access S3 Deployment Bucket
resource "aws_iam_role_policy" "CodeDeploy-EC2-S3" {
  name = "CodeDeploy-EC2-S3"
  role = "${aws_iam_role.CodeDeployEC2ServiceRole.id}"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:Get*",
                "s3:List*"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${var.deployment-bucket}",
                "arn:aws:s3:::${var.deployment-bucket}/*"
            ]
        }
    ]
}
EOF
}

# IAM role for codedeploy application
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

#IAM Policy for codedeploy application
resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = "${aws_iam_role.CodeDeployServiceRole.name}"
}

#Code Deployment Application
resource "aws_codedeploy_app" "csye6225-webapp" {
  name = "${var.csye6225-webapp}"
}

#Code deployment Group
resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name              = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name = "csye6225-webapp-deployment"
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  autoscaling_groups = ["${aws_autoscaling_group.auto-scaling-group.name}"]
  deployment_style {
    deployment_type = "IN_PLACE"
  }
  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "EC2 Instance"
  }
  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}

#CircleCI Policies

data "aws_iam_user" "CircleCI" {
  user_name = "${var.circleCI_username}"
}

#Policy to upload artifacts to S3
resource "aws_iam_policy" "CircleCI-Upload-To-S3" {
  name = "CircleCI-Upload-To-S3"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:Get*",
        "s3:List*"
      ],
      "Resource": [
        "arn:aws:s3:::${var.deployment-bucket}",
        "arn:aws:s3:::${var.deployment-bucket}/*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "attachment" {
  user= "${data.aws_iam_user.CircleCI.user_name}"
  policy_arn = "${aws_iam_policy.CircleCI-Upload-To-S3.arn}"
}

#Policy to access EC2
resource "aws_iam_policy" "circleci-ec2-ami" {
name = "circleci-ec2-ami"
policy = <<EOF
{
"Version": "2012-10-17",
"Statement": [
  {
    "Effect": "Allow",
    "Action": [
      "ec2:AttachVolume",
      "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": [
        "arn:aws:s3:::${var.deployment-bucket}",
        "arn:aws:s3:::${var.deployment-bucket}/*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "ec2_attachment" {
  user= "${data.aws_iam_user.CircleCI.user_name}"
  policy_arn = "${aws_iam_policy.circleci-ec2-ami.arn}"
}

#Policy to allow Circle CI to make deployment API call
resource "aws_iam_policy" "CircleCI-Code-Deploy" {
  name = "CircleCI-Code-Deploy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:RegisterApplicationRevision",
                "codedeploy:GetApplicationRevision"
            ],
            "Resource": [
                "arn:aws:codedeploy:${var.region}:${var.deployment_account_number}:application:${var.csye6225-webapp}"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:CreateDeployment",
                "codedeploy:GetDeployment"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:GetDeploymentConfig"
            ],
            "Resource": [
                "arn:aws:codedeploy:${var.region}:${var.deployment_account_number}:deploymentconfig:CodeDeployDefault.OneAtATime",
                "arn:aws:codedeploy:${var.region}:${var.deployment_account_number}:deploymentconfig:CodeDeployDefault.HalfAtATime",
                "arn:aws:codedeploy:${var.region}:${var.deployment_account_number}:deploymentconfig:CodeDeployDefault.AllAtOnce"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "deployment_attachment" {
  user= "${data.aws_iam_user.CircleCI.user_name}"
  policy_arn = "${aws_iam_policy.CircleCI-Code-Deploy.arn}"
}

#Policy to allow access to Cloud watch agent
resource "aws_iam_role_policy_attachment" "CloudWatchAgent" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
}

resource "aws_iam_role_policy_attachment" "SNSAcess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
  role       = "${aws_iam_role.CodeDeployEC2ServiceRole.name}"
}

###################################################################
#Load Balancer Security Group
resource "aws_security_group" "lb-security-group" {
  name   = "lb-security-group"
  vpc_id = "${aws_vpc.csye6225_vpc.id}"
  ingress {
    from_port  = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # ingress {
  #   from_port  = 22
  #   to_port = 22
  #   protocol = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }
  ingress {
    from_port  = 8080
    to_port = 8080
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "tomcat"
  }
  ingress {
    from_port  = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
#Load Balancer Configuration
resource "aws_lb" "load-balancer" {
  name               = "load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.lb-security-group.id}"]
  subnets            = ["${aws_subnet.csye6225_subnet.*.id[0]}","${aws_subnet.csye6225_subnet.*.id[1]}"]
  tags = {
    Environment      = "development"
  }
}
#Listener for Load Balancer
resource "aws_lb_listener" "load-listener" {
  load_balancer_arn = "${aws_lb.load-balancer.arn}"
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = "${var.ssl_certificate_arn}"
  default_action {
    target_group_arn = "${aws_lb_target_group.target-group.arn}"
    type             = "forward"
  }
}
#Assigning target group 
resource "aws_lb_target_group" "target-group" {
  name        = "target-grp"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = "${aws_vpc.csye6225_vpc.id}"
  target_type = "instance"
  stickiness {
    type = "lb_cookie"
    enabled = true
    cookie_duration = "180"
  }
}
# resource "aws_lb_target_group_attachment" "TG-Attach" {
#   target_group_arn = "${aws_lb_target_group.target-group.arn}"
#   target_id        = "${aws_instance.webapp.id}"
#   port             = 8080
# }

#Autoscale Configuration
resource "aws_launch_configuration" "launch-configuration" {
  name                        = "launch-configuration"
  image_id                    = "${var.ami_id}"
  instance_type               = "t2.micro"
  key_name                    = "${var.ssh_keyname}"
  associate_public_ip_address = true
  user_data                   = <<-EOF
                #!/bin/bash
                touch /home/ubuntu/configuaration.properties
                echo "dbName=${var.database_name}" >> /home/ubuntu/configuaration.properties
                echo "dbUserName=${var.database_user}" >> /home/ubuntu/configuaration.properties
                echo "dbPassword=${var.database_password}" >> /home/ubuntu/configuaration.properties
                echo "dbHostName=${aws_db_instance.database_instance.endpoint}" >> /home/ubuntu/configuaration.properties
                echo "bucketName=${var.bucketname}" >> /home/ubuntu/configuaration.properties
                EOF
  iam_instance_profile        = "${aws_iam_instance_profile.EC2-CSYE6225.name}"
  security_groups             = ["${aws_security_group.application.id}"]

  lifecycle {
    create_before_destroy     = true
  }
}
resource "aws_autoscaling_group" "auto-scaling-group" {
  name                    = "auto-scaling-group"
  launch_configuration    = "${aws_launch_configuration.launch-configuration.id}"
  min_size                = 2
  max_size                = 5
  desired_capacity        = 2
  vpc_zone_identifier     = ["${aws_subnet.csye6225_subnet.*.id[1]}"]
  default_cooldown        = 60
  health_check_type       = "EC2"
  target_group_arns       = ["${aws_lb_target_group.target-group.arn}"]
  lifecycle {
    create_before_destroy = true
  }
  tag {
    key                   = "Name"
    value                 = "New Instance"
    propagate_at_launch   = true
  }
}
#Autoscaling Policy to Scale Up
resource "aws_autoscaling_policy" "ScaleUpPolicy" {
  name                   = "ScaleUpPolicy"
  cooldown               = 60
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.auto-scaling-group.name}"
}
#CloudWatch Alarms for High CPU usage for Autoscaling
resource "aws_cloudwatch_metric_alarm" "HighCPUAlarm" {
  alarm_name             = "HighCPUAlarm"
  comparison_operator    = "GreaterThanThreshold"
  evaluation_periods     = "2"
  metric_name            = "CPUUtilization"
  namespace              = "AWS/EC2"
  period                 = "180"
  statistic              = "Average"
  threshold              = "90"
  dimensions             = {
    AutoScalingGroupName = "${aws_autoscaling_group.auto-scaling-group.name}"
  }
  alarm_description      = "CPU utilization for higher usage"
  alarm_actions          = ["${aws_autoscaling_policy.ScaleUpPolicy.arn}"]
}
#Autoscaling Policy to Scale Down
resource "aws_autoscaling_policy" "ScaleDownPolicy" {
  name                   = "ScaleDownPolicy"
  cooldown               = 60
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.auto-scaling-group.name}"
}
#CloudWatch Alarms for Low CPU usage for Autoscaling
resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  alarm_name             = "CPUAlarmLow"
  comparison_operator    = "LessThanThreshold"
  evaluation_periods     = "2"
  metric_name            = "CPUUtilization"
  namespace              = "AWS/EC2"
  period                 = "180"
  statistic              = "Average"
  threshold              = "50"
  dimensions             = {
    AutoScalingGroupName = "${aws_autoscaling_group.auto-scaling-group.name}"
  }
  alarm_description      = "CPU utilization for less usage"
  alarm_actions          = ["${aws_autoscaling_policy.ScaleDownPolicy.arn}"]
}

#Route 53 Configuration
data "aws_route53_zone" "route-host" {
  name = "${var.dns-name}"
}
#Route Record
resource "aws_route53_record" "route53_record" {
  zone_id                  = "${data.aws_route53_zone.route-host.zone_id}"
  name                     = "www.${data.aws_route53_zone.route-host.name}"
  type                     = "A"

  alias {
    name                   = "${aws_lb.load-balancer.dns_name}"
    zone_id                = "${aws_lb.load-balancer.zone_id}"
    evaluate_target_health = true
  }
}

##################################################################################################################################
# Creates S3 Lambda Bucket for Storing Latest Lambda Function
resource "aws_s3_bucket" "lambda-bucket" {
  bucket = "${var.lambda-bucket}"
  acl    = "private"
  force_destroy = true

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  lifecycle_rule {
    enabled = true
    transition {
      days = 30
      storage_class = "STANDARD_IA"
    }
  }
}
# Creates S3 bucket policy to restrict public access
resource "aws_s3_bucket_public_access_block" "lambda-bucket" {
  bucket = "${aws_s3_bucket.lambda-bucket.id}"

  block_public_acls   = false
  ignore_public_acls = false
  block_public_policy = true
  restrict_public_buckets = true

}
#IAM Lambda role to be attached Lambda function
resource "aws_iam_role" "LambdaRole" {
  name = "iam_for_lambda"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
#Creates policy to access Lambda 
resource "aws_iam_policy" "lambda-policy" {
  name = "lambda-policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
          "s3:Get*",
          "s3:List*"
          ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:*"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
  ]
}
EOF
}
#Attach Lambda role and policy to Role
resource "aws_iam_role_policy_attachment" "lambda-role" {
  policy_arn = "${aws_iam_policy.lambda-policy.arn}"
  role       = "${aws_iam_role.LambdaRole.name}"
}
resource "aws_iam_role_policy_attachment" "AWSLambdaBasicExecutionRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = "${aws_iam_role.LambdaRole.name}"
}
resource "aws_iam_role_policy_attachment" "AmazonSESFullAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
  role       = "${aws_iam_role.LambdaRole.name}"
}
resource "aws_iam_role_policy_attachment" "AmazonSNSFullAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
  role       = "${aws_iam_role.LambdaRole.name}"
}
resource "aws_iam_role_policy_attachment" "AmazonDynamoDBFullAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
  role       = "${aws_iam_role.LambdaRole.name}"
}
resource "aws_iam_role_policy_attachment" "AmazonS3ReadOnlyAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
  role       = "${aws_iam_role.LambdaRole.name}"
}
# SNS Topic
resource "aws_sns_topic" "password_reset" {
  name = "password_reset"
}
# SNS Topic Subsciption
resource "aws_sns_topic_subscription" "password_reset_subscription" {
  topic_arn = "${aws_sns_topic.password_reset.arn}"
  protocol = "lambda"
  endpoint = "${aws_lambda_function.lambda_email.arn}"
}

# Lambda Permission
resource "aws_lambda_permission" "add-sns" {
    statement_id = "AllowExecutionFromSNS"
    action = "lambda:InvokeFunction"
    function_name = "${aws_lambda_function.lambda_email.arn}"
    principal = "sns.amazonaws.com"
    source_arn = "${aws_sns_topic.password_reset.arn}"
}
resource "aws_lambda_permission" "add-s3-bucket" {
    statement_id = "AllowExecutionFromS3Bucket"
    action = "lambda:InvokeFunction"
    function_name = "${aws_lambda_function.lambda_email.arn}"
    principal = "s3.amazonaws.com"
    source_arn = "${aws_s3_bucket.lambda-bucket.arn}"
}
# Create Lambda Function
resource "aws_lambda_function" "lambda_email" {
  # s3_bucket = "${var.lambda-bucket}"
  # s3_key = "EmailTrigger.jar"
  filename = "EmailTrigger.zip"
  function_name = "EmailReset"
  role = "${aws_iam_role.LambdaRole.arn}"
  handler = "EmailTrigger::handleRequest"
  runtime = "java8"
  memory_size = "512"
  timeout = "15"
  environment {
    variables = {
      Domain = "${var.dns-name}"
    }
  }
}

# Creates Policy to upload email artifact to S3
resource "aws_iam_policy" "CircleCILambdaS3Upload" {
  name = "CircleCILambdaS3Upload"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:Get*",
        "s3:List*"
      ],
      "Resource": [
        "arn:aws:s3:::${var.lambda-bucket}",
        "arn:aws:s3:::${var.lambda-bucket}/*"
      ]
    }
  ]
}
EOF
}
resource "aws_iam_user_policy_attachment" "lambda-policy-attachment" {
  user= "${data.aws_iam_user.CircleCI.user_name}"
  policy_arn = "${aws_iam_policy.CircleCILambdaS3Upload.arn}"
}
# Creates Policy for CircleCI to make email deployment calls
resource "aws_iam_policy" "CircleCI-Email-Deploy" {
  name = "CircleCI-Email-Deploy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:UpdateFunctionCode"
            ],
            "Resource": "${aws_lambda_function.lambda_email.arn}"
        }
    ]
}
EOF
}
resource "aws_iam_user_policy_attachment" "email_deployment_attachment" {
  user= "${data.aws_iam_user.CircleCI.user_name}"
  policy_arn = "${aws_iam_policy.CircleCI-Email-Deploy.arn}"
}
