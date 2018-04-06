/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_NDEBUG 0
#define LOG_TAG "ClearKeyCryptoPlugin"
#include <utils/Log.h>

//#include <openssl/aes.h>

#ifndef USE_AES_TA
#include <openssl/aes.h>
#include <openssl/evp.h>
#else
extern "C" {
#include "aes_crypto.h"
}

/* Map between OP TEE TA and OpenSSL */
#define AES_BLOCK_SIZE CTR_AES_BLOCK_SIZE
#endif

#include "AesCtrDecryptor.h"

namespace clearkeydrm {

static const size_t kBlockBitCount = kBlockSize * 8;

AesCtrDecryptor::AesCtrDecryptor() {
#ifdef USE_AES_TA
  TEE_crypto_init();
#endif
}

AesCtrDecryptor::~AesCtrDecryptor() {
#ifdef USE_AES_TA
  TEE_crypto_close();
#endif
}

android::status_t AesCtrDecryptor::decrypt(const android::Vector<uint8_t>& key,
        const Iv iv, const uint8_t* source,
        uint8_t* destination,
        const SubSample* subSamples,
        size_t numSubSamples,
	size_t* bytesDecryptedOut,
	bool secure) {
    uint32_t blockOffset = 0;
    uint8_t previousEncryptedCounter[kBlockSize];
    memset(previousEncryptedCounter, 0, kBlockSize);

    size_t offset = 0;
    Iv opensslIv;

#ifndef USE_AES_TA
    AES_KEY opensslKey;
    AES_set_encrypt_key(key.array(), kBlockBitCount, &opensslKey);
#endif
    memcpy(opensslIv, iv, sizeof(opensslIv));

    for (size_t i = 0; i < numSubSamples; ++i) {
        const SubSample& subSample = subSamples[i];

        if (subSample.mNumBytesOfClearData > 0) {
#ifdef USE_AES_TA
	  if (secure)
	    TEE_copy_secure_memory(source, destination,
				   subSample.mNumBytesOfClearData, offset);
	  else
#endif
            memcpy(destination + offset, source + offset,
                    subSample.mNumBytesOfClearData);

            offset += subSample.mNumBytesOfClearData;
        }

        if (subSample.mNumBytesOfEncryptedData > 0) {
#ifndef USE_AES_TA
            AES_ctr128_encrypt(source + offset, destination + offset,
                    subSample.mNumBytesOfEncryptedData, &opensslKey,
                    opensslIv, previousEncryptedCounter,
                    &blockOffset);
#else
            TEE_AES_ctr128_encrypt(source, destination,
                    subSample.mNumBytesOfEncryptedData, (const char*)key.array(),
                    opensslIv, previousEncryptedCounter,
		    &blockOffset, offset, secure);
#endif
            offset += subSample.mNumBytesOfEncryptedData;
        }
    }

    *bytesDecryptedOut = offset;

    return android::OK;
}

} // namespace clearkeydrm
