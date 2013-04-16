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

"""
Codec implementing HeaderDiff format.
This implementation does not target efficiency but readability.
"""

from struct import pack, unpack
import zlib

from headerDiffCodec import HeaderDiffCodec, IndexedHeader, HeaderRepresentation
from headerDiffCodec import INDEXED_REPRESENTATION, DELTA_REPRESENTATION, NO_INDEXING, INCREMENTAL_INDEXING, SUBSTITUTION_INDEXING

class HeaderDiffKeepCodec(HeaderDiffCodec):
  """
  Codec implementing HeaderDiff format.
  """
  def __init__(self,
      maxIndexedSize,
      **kwargs
      ):
    super(HeaderDiffKeepCodec, self).__init__(maxIndexedSize, **kwargs)
    
    self.encodedHeaders = set()
    self.decodedHeaders = set()

  ######################
  ##   Decoder Part   ##
  ######################

  def decodeHeaders(self, stream, isRequest):
    """
    Method for decoding a set of headers.
    """
    self.decodedStream = stream[8:]
    self.decodedStreamIndex = 0
    # If Deflate was used, apply Inflate
    if self.windowSize != None:
      self.decodedStream = self.decomp.decompress(stream)
    # Initialize variables
    keptHeaders = {}
    for i in self.decodedHeaders:
      keptHeaders[i] = self.indexedHeadersDecoder[i]
    previousHeaders = self.decodedHeaders
    self.decodedHeaders = set()

    # List of decoded headers
    headers = []
    removedHeaders = []
    newHeaders = []

    # Decode number of headers
    nb = self.readNextByte()
    # Set the right table (see Section 3.1.2 Name Table)
    headerNamesTable = (self.headerNamesDecoderRequestTable if isRequest
                        else self.headerNamesDecoderResponseTable)
    
    # Decode headers
    while len(headers) + len(removedHeaders) < nb:
      #################################
      ## Check size of indexed data  ##
      #################################
      # Remark: this is not strictly necessary, but it allows
      # ensuring that encoder has the right behavior
      if self.indexedHeadersSizeDecoder > self.indexedHeadersMaxSize:
        raise Exception("Header table size exceeded (%i VS %i)" %
                        (self.indexedHeadersSizeDecoder,
                           self.indexedHeadersMaxSize))
      ###################################
      ## Start decoding of next header ##
      ###################################
      b0 = self.readNextByte()
      if (b0 & 0x80): # Check whether header is already indexed or not
        #####################################################
        ## Decoding of an already indexed header           ##
        ## (see Section 4.2 Indexed Header Representation) ##
        #####################################################
        index = b0 & 0x3f
        if (b0 & 0x40 != 0): # Check long index flag
          # Long index (see Section 4.2.2)
          index = self.readInteger(b0, 14) + 64
        # Add decoded header to the list
        if index in keptHeaders:
          del keptHeaders[index]
          previousHeaders.remove(index)
          removedHeaders.append(index)
        else:
          headers.append(self.indexedHeadersDecoder[index])
          self.decodedHeaders.add(index)
          newHeaders.append(index)
      else:
        #####################################################
        ## Decoding of a header not already indexed        ##
        ## (see Sections 4.3 Literal Header Representation ##
        ## and 4.4 Delta Header Representation)            ##
        #####################################################
        # Initialize variables
        name = '' # Decoded header name
        value = '' # Decoder header value
        # Index of header used as a reference for delta encoding
        # and/or substitution indexing
        referenceIndex = 0
        # Remark: indexing flags are similar for
        # literal and delta representations
        incrementalIndexing = (b0 & 0x30) == 0x20
        substitutionIndexing = (b0 & 0x30) == 0x30
        indexFlag = incrementalIndexing or substitutionIndexing
        # Length of prefix bits (available for encoding an integer)
        #  - 5 bits if no indexing (see 4.3.1 and 4.4.1)
        #  - 4 bits if indexing  (see 4.3.2 and 4.4.2)
        prefixBits = 4 if indexFlag else 5
        if (b0 & 0x40): # Check whether header is encoded as a delta
          ##################################################
          ## Decoding of a delta encoded header           ##
          ## (see Section 4.4 Delta Header Representation)##
          ##################################################
          # Decode index of header referred to in this delta
          referenceIndex = self.readInteger(b0, prefixBits)
          # Name can now be determined based on referenceIndex
          name = self.indexedHeadersDecoder[referenceIndex][0]
          # Also decode common prefix length
          prefixLength = self.readInteger(b0, 0)
        # Below are cases different from delta encoding
        else:
          ####################################################
          ## Decoding of a literally encoded header         ##
          ## (see Section 4.3 Literal Header Representation)##
          ####################################################
          # Determine header name (index+1 is encoded in the stream)
          ref = self.readInteger(b0, prefixBits)
          if ref == 0:
            # Index 0 means new literal string
            name = self.readLiteralString()
            headerNamesTable.append(name)
          else:
            name = headerNamesTable[ref-1]
          # If substitution indexing, decode reference header index
          if substitutionIndexing:
            referenceIndex = self.readInteger(b0, 0)
        ##############################
        ## Decoding of header value ##
        ##############################
        value = self.readLiteralString()
        # If delta representation, apply delta to obtain full value
        if (b0 & 0x40) == 0x40:
          prefix = self.indexedHeadersDecoder[referenceIndex][1]
          value = prefix[:prefixLength]+ value
        # Add decoded headers
        headers.append((name, value))
        ######################################
        ## Apply indexing mode              ##
        ## (see section 3.1.1 Header Table) ##
        ######################################
        if substitutionIndexing:
          # Replace reference header
          reference = self.indexedHeadersDecoder[referenceIndex]
          self.indexedHeadersDecoder[referenceIndex] = (name, value)
          # Reference header value is accessible through reference[1]
          referenceValue = reference[1]
          self.indexedHeadersSizeDecoder+= (len(value)
                                            - len(referenceValue))
          
          if referenceIndex in previousHeaders:
            previousHeaders.remove(referenceIndex)
          self.decodedHeaders.add(referenceIndex)
          newHeaders.append(referenceIndex)
        elif incrementalIndexing:
          # Append to end as a new index
          index = len(self.indexedHeadersDecoder)
          self.indexedHeadersDecoder.append((name, value))
          self.indexedHeadersSizeDecoder+= len(value)
          self.decodedHeaders.add(index)
          newHeaders.append(index)
      
    for h in keptHeaders.values(): 
      headers.append(h)
    self.decodedHeaders |= previousHeaders
    
    return headers

  ######################
  ##   Encoder Part   ##
  ######################

  def encodeHeaders(self, headerTuples, isRequest):
    """
    Method for encoding a set of headers
    """
    # Pre-processing of headers
    keptHeaders = set()
    newHeaders = []

    for he in headerTuples:
      het = (he.name, he.value)
      if het in keptHeaders:
        continue
      if het in self.encodedHeaders:
        keptHeaders.add(het)
        self.encodedHeaders.remove(het)
      else:
        newHeaders.append(he)

    removedHeaders = self.encodedHeaders
    self.encodedHeaders = set(keptHeaders)
    headerTuples = newHeaders
    
    # Before encoding, increment age of indexed headers
    for ih in self.headersTableEncoder:
      self.headersTableEncoder[ih].age+= 1
    # Set the right table
    headerNamesTable = (self.headerNamesEncoderRequestTable if isRequest
                        else self.headerNamesEncoderResponseTable)
    # First, encode the number of headers (single byte)
    self.encodedStream = pack("!B", len(headerTuples) + len(removedHeaders))
    
    # Encode removed headers
    for he in removedHeaders:
      referenceHeader = self.headersTableEncoder[he[0] + he[1]]
      if referenceHeader.index < 64:
        b = 0x80 | referenceHeader.index
        self.encodedStream += pack("!B", b)
      else:
        b = 0xC0
        self.writeInteger(b, 14, referenceHeader.index - 64)
    
    # Then, encode headers
    for he in headerTuples:
      headerName = he.name
      headerValue = he.value
      headerFull = headerName + headerValue
      # Determine representation
      hr = self.determineRepresentation(
        headerName,
        headerValue,
        isRequest)
          
      # Encode representation
      if hr.representation == INDEXED_REPRESENTATION:
        ############################
        ## Indexed representation ##
        ############################
        if hr.referenceHeader.index < 64:
          # Short index (see Section 4.2.1 Short Indexed Header)
          b = 0x80 | hr.referenceHeader.index
          self.encodedStream+= pack("!B", b)
        else:
          # Long index (see Section 4.2.2 Long Indexed Header)
          b = 0xc0
          self.writeInteger(b, 14, hr.referenceHeader.index-64)
        self.encodedHeaders.add((he.name, he.value))
      else:
        #############################################################
        ## Set indexing bits (same process for delta and literal)  ##
        ## (see Sections 4.3 Literal Header and 4.4 Delta Header)  ##
        #############################################################
        # First byte to be encoded (no flag if no indexing)
        b = 0x00
        # Length of prefix bits (available for encoding an integer)
        #  - 5 bits if no indexing (see 4.3.1 and 4.4.1)
        #  - 4 bits if indexing  (see 4.3.2 and 4.4.2)
        prefixBits = 4 if hr.indexing != NO_INDEXING else 5
        if hr.indexing == SUBSTITUTION_INDEXING:
          # Set substitution indexing flag
          b = 0x30
          # Remove replaced header, add new one and update table size
          # (as defined in Section 3.1.1 Header Table)
          del self.headersTableEncoder[hr.referenceHeader.full]
          self.headersTableEncoder[headerFull] = IndexedHeader(
            headerName,
            headerValue,
            hr.referenceHeader.index)
          self.headersTableEncoderSize-=len(hr.referenceHeader.value)
          self.headersTableEncoderSize+=len(headerValue)
          self.encodedHeaders.add((headerName, headerValue))
          if (hr.referenceHeader.name, hr.referenceHeader.value) in self.encodedHeaders:
            self.encodedHeaders.remove((hr.referenceHeader.name, hr.referenceHeader.value))
        elif hr.indexing == INCREMENTAL_INDEXING:
          # Set incremental indexing flag
          b = 0x20
          # Add new header and update table size
          # (as defined in Section 3.1.1 Header Table)
          self.headersTableEncoder[headerFull] = IndexedHeader(
            headerName,
            headerValue,
            len(self.headersTableEncoder))
          self.headersTableEncoderSize+= len(headerValue)
          self.encodedHeaders.add((headerName, headerValue))
        #############################################################
        ## Serialize using delta or literal representation         ##
        ## (see Sections 4.3 Literal Header and 4.4 Delta Header)  ##
        #############################################################
        if self.delta_usage and hr.representation == DELTA_REPRESENTATION:
          # Delta Representation (see Sections 4.4.1 and 4.4.2)
          # Set '01' at the beginning of the byte
          # (delta representation)
          b = b | 0x40
          # Encode reference header index
          self.writeInteger(b, prefixBits, hr.referenceHeader.index)
          # Encode common prefix length
          self.writeInteger(b, 0, hr.commonPrefixLength)
          hr.referenceHeader.delta_usage += 1
        else:
          # Literal Representation (see Sections 4.3.1 / 4.3.2)
          # '00' at the beginning of the byte (nothing to do)
          # Determine index of header name
          # (see Section 3.1.2 Name Table)
          nameIndex = (-1 if headerName not in headerNamesTable
                       else headerNamesTable[headerName])
          # Encode index + 1 (0 represents a new header name)
          self.writeInteger(b, prefixBits, nameIndex+1)
          # In case of new header name, encode name literally
          if nameIndex == -1:
            self.writeLiteralString(headerName)
            headerNamesTable[headerName] = len(headerNamesTable)
          # In case of substitution indexing,
          # encode index of reference header
          if hr.indexing == SUBSTITUTION_INDEXING:
            self.writeInteger(b, 0, hr.referenceHeader.index)
        # Encode value
        if self.delta_usage and hr.representation == DELTA_REPRESENTATION:
          valueToEncode = headerValue[hr.commonPrefixLength:]
        else:
          valueToEncode = headerValue
        self.writeLiteralString(valueToEncode)

    # Return encoded headers
    if self.windowSize != None:
      data = self.comp.compress(self.encodedStream)
      data += self.comp.flush(zlib.Z_SYNC_FLUSH)
    else:
      data = self.encodedStream
    
    # Generate Frame Header
    frame = pack("!HBBL", len(data), 0, 0, 0)
    return frame + data
