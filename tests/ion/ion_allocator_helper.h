/*
 * Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __ION_ALLOCATOR_HELPER_H__
#define __ION_ALLOCATOR_HELPER_H__

#include <stdint.h>

#define ION_DEVICE_NAME "/dev/ion"

namespace media {

class IonAllocator
{
public:
  // Constructor.
  IonAllocator();

  // Destructor.
  ~IonAllocator();

  /* Allocate an ION buffer from the specified ION heap ID. The caller is
     responsible to free the ION buffer by calling the IonAllocator::Free() API.
  
     Note: The current implementation uses the ION ABI as defined in kernel 4.9.
     It does not support the newer ION ABI available in newer kernel. */
  int Allocate(size_t size, uint32_t heap_id);
  void Free();

  /* Map the allocated ION buffer and return its address. This is only possible
     for ION heap which are accessible by the host CPU (not protected by any
     hardware mechanism like TZASC). */
  uint8_t *Map(void);
  void Unmap(void);

  /* This function maps the memory referenced by the allocated ION file
     descriptor and copies it into the specified destination buffer. When the
     specified destination buffer is smaller than the ION buffer, the first
     'dst_size' bytes are copied into the destination buffer.

     Note: When the ION buffer is allocated from a secure ION heap, the memory
     shall not actually be protected by any hardware mechanism to use this API.
     This API is expected to be used to implement a SDP prototype where data is
     decrypted into an ION buffer and then this API copies the data into shared
     memory to allow playback on platforms which do not have an end-to-end SDP
     solution. */ 
  int CopyData(uint8_t *dst, size_t dst_size);

  int GetFileDescriptor(void) {
    return m_ionFd;
  }
  
  size_t GetSize(void) {
    return m_ionSize;
  }

private:
  int m_ionDeviceFd;
  
  int m_ionFd;
  size_t m_ionSize;
  
  uint8_t *m_mappedData;
};

}  // namespace media

#endif  // #ifdef __ION_ALLOCATOR_HELPER_H__
