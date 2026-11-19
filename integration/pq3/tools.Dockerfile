# Copyright the Hyperledger Fabric contributors. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#

FROM ubuntu:24.04

COPY osnadmin /usr/local/bin/osnadmin
COPY pq3-verify /usr/local/bin/pq3-verify

ENTRYPOINT ["/usr/local/bin/osnadmin"]
