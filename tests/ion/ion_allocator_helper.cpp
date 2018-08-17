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

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/ion.h>

#include <fstream>
#include <iostream>

#include "ion_allocator_helper.h"

namespace media {

#define CDM_DLOG() std::cout << "\n" <<__FILE__<<":"<<  __func__ <<":"<< __LINE__ <<"::"

// Constructor.
IonAllocator::IonAllocator() {
  m_ionDeviceFd = open(ION_DEVICE_NAME, O_RDWR);
  if (m_ionDeviceFd < 0) {
    CDM_DLOG() << "Failed to open /dev/ion";
  }
  
  m_ionFd = -1;
  m_ionSize = 0;
  
  m_mappedData = NULL;
}

  
IonAllocator::~IonAllocator()
{
  Free();
  
  if(m_ionDeviceFd >= 0) {
    close(m_ionDeviceFd);
    m_ionDeviceFd = -1;
  }
}
  
  
/* Allocate an ION buffer from the specified ION heap ID. The caller is
   responsible to free the ION buffer by calling the IonAllocator::Free() API.
  
   Note: The current implementation uses the ION ABI as defined in kernel 4.9.
   It does not support the newer ION ABI available in newer kernel. */
int IonAllocator::Allocate(size_t size, uint32_t heap_id)
{
  int status = 0;
  struct ion_allocation_data alloc_data;
  struct ion_handle_data hdl_data;
  struct ion_fd_data fd_data;

  CDM_DLOG() << "Allocate " << size << " bytes from ION heap ID " << heap_id;
  
  if((size == 0) || (heap_id >= 32)) {
    CDM_DLOG() << "Invalid parameter";
    return -1;
  }
  
  if (m_ionDeviceFd < 0) {
    CDM_DLOG() << "Cannot allocate buffer, ION device is invalid";
    return -1;
  }
  
  if(m_ionFd >= 0) {
    CDM_DLOG() << "Ion buffer was already allocated. Free and allocate a new buffer.";
    Free();
  }

  alloc_data.len = size;
  alloc_data.align = 0;
  alloc_data.flags = 0;
  alloc_data.heap_id_mask = 1 << heap_id;
  if (ioctl(m_ionDeviceFd, ION_IOC_ALLOC, &alloc_data) == -1) {
    CDM_DLOG() << "Failed to allocate buffer from ION heap ID " << heap_id;
    return -1;
  }

  fd_data.handle = alloc_data.handle;
  if (ioctl(m_ionDeviceFd, ION_IOC_SHARE, &fd_data) != -1) {
    m_ionFd = fd_data.fd;
    m_ionSize = size;
    m_mappedData = NULL;
  } else {
    status = -1;
    CDM_DLOG() << "Failed to share secure buffer.";
  }
  
  hdl_data.handle = alloc_data.handle;
  (void)ioctl(m_ionDeviceFd, ION_IOC_FREE, &hdl_data);
  
  return status;
}
  
void IonAllocator::Free() {
  /* Make sure the ION buffer is not mapped. */
  Unmap();
  
  if(m_ionFd >= 0) {
    close(m_ionFd);
    m_ionFd = -1;
    m_ionSize = 0;
  }
}

  
uint8_t *IonAllocator::Map(void) {

  if((m_ionFd < 0) || (m_ionSize == 0)) {
    CDM_DLOG() << "Invalid ION buffer";
    return NULL;
  }
  
  if(m_mappedData != NULL) {
    /* Ion is already mapped. Return the address. */
    return m_mappedData;
  }

  // Map the ION buffer
  m_mappedData = (uint8_t *)mmap(0, m_ionSize, PROT_READ | PROT_WRITE, MAP_SHARED, m_ionFd, 0);
  if(m_mappedData == NULL) {
    CDM_DLOG() << "Cannot map ION";
    return NULL;
  }
  
  return m_mappedData;
}

  
void IonAllocator::Unmap(void) {
  if(m_mappedData != NULL) {
    munmap(m_mappedData, m_ionSize);
    m_mappedData = NULL;
  }
}


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
int IonAllocator::CopyData(uint8_t *dst, size_t dst_size)
{
  if(dst == NULL) {
    return -1;
  }
  
  if(Map() == NULL) {
    return -1;
  }

  size_t size = m_ionSize;
  if(dst_size < m_ionSize) {
    /* Specified destination buffer is too small. Perform a partial copy. */
    size = dst_size;
  }
  memcpy(dst, m_mappedData, size);

  CDM_DLOG() << "IonAllocator::CopyData: 0x" << std::hex << " " << (uint32_t)m_mappedData[0] << " " << (uint32_t)m_mappedData[1] << " "
             << (uint32_t)m_mappedData[2] << " " << (uint32_t)m_mappedData[3] << " " << (uint32_t)m_mappedData[4] << std::dec;
  
  Unmap();

  return 0;
}

	
}  // namespace media




