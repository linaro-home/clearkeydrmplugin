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

//#define LOG_NDEBUG 0
#define LOG_TAG "ClearKeyCryptoPlugin"
#include <utils/Log.h>

#include <aes_crypto.h>

#include "AesCtrDecryptorSecure.h"

namespace clearkeydrm {

static const size_t kBlockBitCount = kBlockSize * 8;

android::status_t AesCtrDecryptorSecure::secureDecrypt(
        const char* key,
        const Iv iv, const uint8_t* source,
        uint8_t* destination,
        const SubSample* subSamples,
        size_t numSubSamples,
        size_t* bytesDecryptedOut) {
    uint32_t _numSamples = (uint32_t)numSubSamples;
    sub_sample_t* _subSamples = new sub_sample_t[_numSamples + 1];

    if (_subSamples) {
        uint32_t length = 0;
        Iv opensslIv;
	if (key)
	        memcpy(opensslIv, iv, sizeof(opensslIv));
	else
		memset(opensslIv, 0, sizeof(opensslIv));

        uint32_t i;
        for (i = 0; i < _numSamples; i++) {
            _subSamples[i].clear_bytes = subSamples[i].mNumBytesOfClearData;
            _subSamples[i].encrp_bytes = subSamples[i].mNumBytesOfEncryptedData;
            length += _subSamples[i].clear_bytes + _subSamples[i].encrp_bytes;
        }
	/* set tail flags */
        _subSamples[i].clear_bytes = 0xFFFFFFFF;
        _subSamples[i].encrp_bytes = 0xFFFFFFFF;

        uint32_t offset = 0;
        TEE_AES_ctr128_encrypt_secure(source, destination, _subSamples,
                                   (_numSamples + 1) * sizeof(sub_sample_t),
                                   key, opensslIv, &length);
        *bytesDecryptedOut = length;

	delete []_subSamples;

        return android::OK;
    } else
        return android::ERROR_DRM_UNKNOWN;
}

} // namespace clearkeydrm
