// Copyright (c) 2014-2015, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <fstream>

#include "include_base_utils.h"
#include "account.h"
#include "warnings.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/keccak.h"
}
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "cryptonote_core/cryptonote_format_utils.h"
using namespace std;

// TODO CONFIG
int mode_key_generation = 1; // MyMonero

DISABLE_VS_WARNINGS(4244 4345)

  namespace cryptonote
{
  //-----------------------------------------------------------------
  account_base::account_base()
  {
    set_null();
  }
  //-----------------------------------------------------------------
  void account_base::set_null()
  {
    m_keys = account_keys();
  }
  //-----------------------------------------------------------------
  crypto::secret_key account_base::generate(const crypto::secret_key& recovery_key, bool recover, bool two_random, size_t num_words)
  {
    crypto::secret_key use_recovery_key;
    if (recover)
    {
      bool half_seed = false;
      // for debugging only
      if (num_words == 12)
      {
        half_seed = true;
      }
      // TODO: finish implementation and test
      // this is also for when recovery from seed hex is supported.
      size_t len = sizeof(recovery_key.data);
      while ((len > 0) && (! recovery_key.data[len - 1])) {
        --len;
      }
      if (len <= sizeof(crypto::secret_key) / 2) // TODO refactor with elsewhere
      {
        std::cout << "key length minus end null bytes less than normal size/2" << std::endl;
        if ((num_words) && (num_words != 12))
        {
          throw std::runtime_error("Seed words used, but the number doesn't match expected number for a recovery key half filled.");
        }
        half_seed = true;
      }
      else if (num_words == 12)
      {
          throw std::runtime_error("Seed words used, with half the normal number, but the recovery key doesn't look half filled.");
      }
      std::cout << "num_words:  " << num_words << "  half_seed? " << half_seed << std::endl;
      if (! half_seed)
      {
        use_recovery_key = recovery_key;
      }
      else
      {
        if (mode_key_generation == 0)
        {
          use_recovery_key = recovery_key;
          memcpy(use_recovery_key.data + 16, use_recovery_key.data, 16);  // if electrum 12-word seed, duplicate
        }
        else if (mode_key_generation == 1)
        {
          keccak((uint8_t *)&recovery_key.data, sizeof(crypto::secret_key) / 2, (uint8_t *)&use_recovery_key.data, sizeof(crypto::secret_key));
        }
        else
        {
          // TODO: throw runtime exception
        }
        std::cout << "use_recovery_key.data:  " << epee::string_tools::pod_to_hex(use_recovery_key.data) << std::endl;
        // because of keccak used to expand can't reverse this back to the twelve-word seed, only to new twenty-four words.
      }

      // recovery key deemed acceptable, assign to stored seed
      m_keys.m_seed = recovery_key;
    }

    crypto::secret_key first = generate_keys(m_keys.m_account_address.m_spend_public_key, m_keys.m_spend_secret_key, use_recovery_key, recover);

    if (! recover)
    {
      m_keys.m_seed = first;
    }

    // rng for generating second set of keys is hash of first rng.  means only one set of electrum-style words needed for recovery
    crypto::secret_key second;

    if (mode_key_generation == 0)
    {
      // monero behavior
      keccak((uint8_t *)&m_keys.m_spend_secret_key, sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));
    }
    else if (mode_key_generation == 1)
    {
      // mymonero behavior
      // "first" is the rng / provided seed recovery key prior to sc_reduce32().
      // note that in original behavior, sc_reduce and a halving is done during
      // rng generation. see random_scalar().
      keccak((uint8_t *)&first, sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));
    }

    generate_keys(m_keys.m_account_address.m_view_public_key, m_keys.m_view_secret_key, second, two_random ? false : true);

    struct tm timestamp;
    timestamp.tm_year = 2014 - 1900;  // year 2014
    timestamp.tm_mon = 6 - 1;  // month june
    timestamp.tm_mday = 8;  // 8th of june
    timestamp.tm_hour = 0;
    timestamp.tm_min = 0;
    timestamp.tm_sec = 0;

    if (recover)
    {
      m_creation_timestamp = mktime(&timestamp);
    }
    else
    {
      m_creation_timestamp = time(NULL);
    }
    return m_keys.m_seed;
  }
  //-----------------------------------------------------------------
  const account_keys& account_base::get_keys() const
  {
    return m_keys;
  }
  //-----------------------------------------------------------------
  std::string account_base::get_public_address_str(bool testnet)
  {
    //TODO: change this code into base 58
    return get_account_address_as_str(testnet, m_keys.m_account_address);
  }
  //-----------------------------------------------------------------
}
