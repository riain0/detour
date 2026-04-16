# ── Detour broker AWS Fargate ───────────────────────────────────────────────
#
# Add this to your dev environment Terraform config.
# Deploy once per env all services share one broker.
#
# Prerequisites:
#   - An existing VPC and subnets (referenced via var.vpc_id / var.subnet_ids)
#   - An ACM certificate (ALB requires HTTPS for HTTP/2 / gRPC)
#
# Variables to add:
#   variable "detour_enabled"     { type = bool;         default = false }
#   variable "vpc_id"             { type = string }
#   variable "subnet_ids"         { type = list(string) }
#   variable "detour_broker_cert" { type = string }       # ACM cert ARN
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "detour_broker" {
  count                    = var.detour_enabled ? 1 : 0
  family                   = "detour-broker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.detour_broker_exec[0].arn

  container_definitions = jsonencode([
    {
      name      = "broker"
      image     = "ghcr.io/riain0/detour-broker:latest"
      essential = true
      portMappings = [{ containerPort = 8080, protocol = "tcp" }]
      environment = [
        { name = "DETOUR_AUTH_MODE", value = "session-id" }
      ]
    }
  ])
}

resource "aws_ecs_service" "detour_broker" {
  count           = var.detour_enabled ? 1 : 0
  name            = "detour-broker"
  cluster         = aws_ecs_cluster.detour[0].id
  task_definition = aws_ecs_task_definition.detour_broker[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.detour_broker[0].id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.detour_broker[0].arn
    container_name   = "broker"
    container_port   = 8080
  }
}

resource "aws_ecs_cluster" "detour" {
  count = var.detour_enabled ? 1 : 0
  name  = "detour"
}

resource "aws_lb" "detour_broker" {
  count              = var.detour_enabled ? 1 : 0
  name               = "detour-broker"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.subnet_ids
}

resource "aws_lb_target_group" "detour_broker" {
  count            = var.detour_enabled ? 1 : 0
  name             = "detour-broker"
  port             = 8080
  protocol         = "HTTP"
  protocol_version = "GRPC"
  target_type      = "ip"
  vpc_id           = var.vpc_id
}

resource "aws_lb_listener" "detour_broker" {
  count             = var.detour_enabled ? 1 : 0
  load_balancer_arn = aws_lb.detour_broker[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.detour_broker_cert

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.detour_broker[0].arn
  }
}

resource "aws_security_group" "detour_broker" {
  count  = var.detour_enabled ? 1 : 0
  name   = "detour-broker"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "detour_broker_exec" {
  count = var.detour_enabled ? 1 : 0
  name  = "detour-broker-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "detour_broker_exec" {
  count      = var.detour_enabled ? 1 : 0
  role       = aws_iam_role.detour_broker_exec[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

locals {
  detour_broker_url = var.detour_enabled ? "https://${aws_lb.detour_broker[0].dns_name}" : ""
}
