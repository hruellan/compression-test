# Copyright (c) 2012-2013, Canon Inc. 
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted only for the purpose of developing standards
# within the HTTPbis WG and for testing and promoting such standards within the
# IETF Standards Process. The following conditions are required to be met:
# - Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# - Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# - Neither the name of Canon Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY CANON INC. AND ITS CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL CANON INC. AND ITS CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import collections
import zlib

from headerDiffCodec import HeaderDiffCodec, IndexedHeader
from headerDiffCodec import DELTA_FULL, DELTA_BOUND, DELTA_MAX

from .. import BaseProcessor,  spdy_dictionary

#####################################################
## Class for representing a Header: (name, value)  ##
#####################################################
class HeaderTuple(object):
  def __init__(self, name, value):
    self.name = name
    self.value = value
    
  @classmethod
  def from_dict(cls, d):
    """Convert a dict of headers to a list of HeaderTuple."""
    return [HeaderTuple(k, v) for k, v in d.items()]
  
  @classmethod
  def split_from_dict(cls, d):
    """Convert a dict of headers to a list of HeaderTuple, splitting
    the cookies."""
    lst = []
    for k, v in d.items():
      if k == "cookie":
        lst.extend(HeaderTuple(k, vs.strip()) for vs in v.split(";"))
      else:
        lst.extend(HeaderTuple(k, vs.strip()) for vs in v.split("\0"))
    return lst
  
  def __str__(self):
    return self.name + ":" + self.value

  def __repr__(self):
    return self.name + ":" + self.value

BUFFER_SIZE = "buffer"
DEFLATE_SIZE = "deflate"
DELTA_USAGE = "delta"
DELTA_TYPE = "delta_type"
HUFFMAN = "huffman"

def parse_bool(value):
  if value is None:
    return True
  if value.lower() == "false":
    return False
  else:
    return True

def parse_delta(value):
  if value is None:
    return DELTA_FULL, ""

  value = value.strip()
  try:
    vint = int(value)
    return DELTA_MAX, vint
  except ValueError:
    pass
  
  if value:
    return DELTA_BOUND, value.strip("\"'")
  else:
    return DELTA_FULL, ""

param_functions = {
  BUFFER_SIZE: int,
  DEFLATE_SIZE: int,
  DELTA_USAGE: parse_bool,
  DELTA_TYPE: parse_delta,
  HUFFMAN: parse_bool,
}

#####################################################
## Interface for the HeaderDiff codec              ##
#####################################################
class Processor(BaseProcessor):
  def __init__(self, options, is_request, params):
    BaseProcessor.__init__(self, options, is_request, params)
    
    param_dict = {
      BUFFER_SIZE: 32768,
      DEFLATE_SIZE: None,
      DELTA_USAGE: True,
      DELTA_TYPE: (DELTA_FULL, ""),
      HUFFMAN: False,
    }
    for param in params:
      if "=" in param:
        name, value = param.split("=", 1)
      else:
        name = param
        value = None
      if name in param_functions:
        param_dict[name] = param_functions[name](value)
      else:
        param_dict[name] = value
    
    self.codec = HeaderDiffCodec(
      param_dict[BUFFER_SIZE],
      windowSize=param_dict[DEFLATE_SIZE],
      dict=spdy_dictionary.spdy_dict,
      delta_usage=param_dict[DELTA_USAGE],
      delta_type=param_dict[DELTA_TYPE],
      huffman=param_dict[HUFFMAN],
      isRequest=is_request,
      )
  
  def compress(self, in_headers, host):
    hdrs = dict(in_headers)
    hdrs = HeaderTuple.split_from_dict(hdrs)
    
    frame = self.codec.encodeHeaders(hdrs, self.is_request)
    return frame
  
  def decompress(self, compressed):
    headers = self.codec.decodeHeaders(compressed, self.is_request)
    hdrs = {}
    for k, v in headers:
      if k in hdrs:
        if k == "cookie":
          hdrs[k] += ";" + v
        else:
          hdrs[k] += "\0" + v
      else:
        hdrs[k] = v
    
    return hdrs
