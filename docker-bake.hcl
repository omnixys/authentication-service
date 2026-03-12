 # @license GPL-3.0-or-later
 # Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 #
 # This program is free software: you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation, either version 3 of the License, or
 # (at your option) any later version.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 # See the GNU General Public License for more details.
 #
 # For more information, visit <https://www.gnu.org/licenses/>.
 
# ---------------------------------------------------------------------------------------
# 🧱 docker-bake.hcl – Omnixys Bake Setup
# ---------------------------------------------------------------------------------------
# Build orchestration for Omnixys Node-based microservices using HashiCorp Docker Bake.
# Aufruf mit :
# APP_VERSION=$(node -p "require('./package.json').version") docker buildx bake
# ---------------------------------------------------------------------------------------

variable "APP_NAME" {
  default = "authentication"
}

# Pass APP_VERSION via CLI:
variable "APP_VERSION" {
  default = "dev"
}

variable "NODE_VERSION" {
  default = "24.10.0"
}

variable "CREATED" {
  default = timestamp()
}

variable "REVISION" {
  default = "local-dev"
}

# ---------------------------------------------------------------------------------------
# Target Group
# ---------------------------------------------------------------------------------------

group "default" {
  targets = ["build"]
}

target "build" {
  dockerfile = "./Dockerfile"
  context = "."

  secret = [
    "id=omnixys_token,src=.secrets/omnixys_token"
  ]

  args = {
    NODE_VERSION = "${NODE_VERSION}"
    APP_NAME     = "${APP_NAME}"
    APP_VERSION  = "${APP_VERSION}"
    CREATED      = "${CREATED}"
    REVISION     = "${REVISION}"
  }

  labels = {
    "org.opencontainers.image.title"         = "omnixys-${APP_NAME}-service"
    "org.opencontainers.image.version"       = "${APP_VERSION}"
    "org.opencontainers.image.created"       = "${CREATED}"
    "org.opencontainers.image.revision"      = "${REVISION}"
    "org.opencontainers.image.source"        = "https://github.com/omnixys/omnixys-${APP_NAME}-service"
    "org.opencontainers.image.licenses"      = "GPL-3.0-or-later"
    "org.opencontainers.image.vendor"        = "omnixys"
    "org.opencontainers.image.authors"       = "caleb.gyamfi@omnixys.com"
  }

  tags = [
    "omnixys/${APP_NAME}-service:latest",
    "omnixys/${APP_NAME}-service:${APP_VERSION}"
  ]

platforms = ["linux/arm64"]
output = ["type=docker"]

}
