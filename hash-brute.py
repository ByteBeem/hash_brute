import hashlib
import bcrypt
from Crypto.Hash import MD4
import argon2
import zlib
from passlib.hash import argon2 as passlib_argon2
from multiprocessing import Pool, cpu_count



def worker(args):
    hashed_value, hash_type, line = args
    print(f"Trying password: {line}")

            # Calculate the hash for each word in the wordlist
            hash_result = None
            if hash_type == 1:
                hash_result = hashlib.md2(line.encode()).hexdigest()
            elif hash_type == 2:
                 hash_result = MD4.new(line.encode()).hexdigest()
            elif hash_type == 3:
                hash_result = hashlib.md5(line.encode()).hexdigest()
            elif hash_type == 4:
                hash_result = hashlib.sha1(line.encode()).hexdigest()
            elif hash_type == 5:
                hash_result = hashlib.sha224(line.encode()).hexdigest()
            elif hash_type == 6:
                hash_result = hashlib.sha256(line.encode()).hexdigest()
            elif hash_type == 7:
                hash_result = hashlib.sha384(line.encode()).hexdigest()
            elif hash_type == 8:
                hash_result = hashlib.sha512(line.encode()).hexdigest()
            elif hash_type == 9:
                hash_result = hashlib.sha3_224(line.encode()).hexdigest()
            elif hash_type == 10:
                hash_result = hashlib.sha3_256(line.encode()).hexdigest()
            elif hash_type == 11:
                hash_result = hashlib.sha3_384(line.encode()).hexdigest()
            elif hash_type == 12:
                hash_result = hashlib.sha3_512(line.encode()).hexdigest()
            elif hash_type == 13:
                hash_result = hex(zlib.crc32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 14:
                hash_result = hex(zlib.crc32(line.encode(), zlib.crc32c))[2:]  # Remove '0x' prefix
            elif hash_type == 15:
                hash_result = hex(zlib.crc64(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 16:
                hash_result = hashlib.new('whirlpool', line.encode()).hexdigest()
            elif hash_type == 17:
                hash_result = hashlib.blake2s(line.encode()).hexdigest()
            elif hash_type == 18:
                hash_result = hashlib.new('ripemd128', line.encode()).hexdigest()
            elif hash_type == 19:
                hash_result = hashlib.new('ripemd160', line.encode()).hexdigest()
            elif hash_type == 20:
                hash_result = hashlib.new('ripemd256', line.encode()).hexdigest()
            elif hash_type == 21:
                hash_result = hashlib.new('ripemd320', line.encode()).hexdigest()
            elif hash_type == 22:
                hash_result = hashlib.new('tiger192,3', line.encode()).hexdigest()
            elif hash_type == 23:
                hash_result = hashlib.new('skein256', line.encode()).hexdigest()
            elif hash_type == 24:
                hash_result = hashlib.new('skein512', line.encode()).hexdigest()
            elif hash_type == 25:
                hash_result = hashlib.new('gost94', line.encode()).hexdigest()
            elif hash_type == 26:
                hash_result = hex(zlib.adler32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 27:
                hash_result = hex(zlib.fletcher32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 28:
                hash_result = hex(hashlib.fnv1_32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 29:
                hash_result = hex(hashlib.fnv1a_32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 30:
                hash_result = hex(hashlib.murmurhash2_32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 31:
                hash_result = hex(hashlib.murmurhash3_32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 32:
                hash_result = hex(hashlib.cityhash.cityhash32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 33:
                hash_result = hex(hashlib.cityhash.cityhash64(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 34:
                hash_result = hex(hashlib.xxhash.xxh32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 35:
                hash_result = hex(hashlib.xxhash.xxh64(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 36:
                hash_result = hex(hashlib.jenkins(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 37:
                hash_result = hex(hashlib.siphash24(line.encode(), 0, 0))[2:]  # Remove '0x' prefix
            elif hash_type == 38:
                hash_result = hashlib.new('pearson', line.encode()).hexdigest()
            elif hash_type == 39:
                hash_result = hex(hashlib.elf(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 40:
                hash_result = hex(hashlib.jenkins(line.encode(), 0))[2:]  # Remove '0x' prefix
            elif hash_type == 41:
                hash_result = hex(hashlib.spooky_32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 42:
                hash_result = hex(hashlib.farmhash.fingerprint32(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 43:
                hash_result = hex(hashlib.farmhash.fingerprint64(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 44:
                hash_result = hex(hashlib.hdlc(line.encode()))[2:]  # Remove '0x' prefix
            elif hash_type == 45:
                # bcrypt password hashing
                if bcrypt.checkpw(line.encode(), hashed_value.encode()):
                    print(f"Hash cracked! The original value is: {line}")
                    print(f"Found hash type: bcrypt (hash type 45)")
                    return
                else:
                    continue
            elif hash_type == 46:
                # Argon2 password hashing
                argon2_hash = passlib_argon2.identify(hashed_value)
                hasher = argon2.PasswordHasher()
                if argon2_hash:
                    for line in file:
                        line = line.strip()
                        try:
                            if hasher.verify(hashed_value, line):
                                print(f"Hash cracked! The original value is: {line}")
                                print(f"Found hash type: {argon2_hash}")
                                return
                        except:
                            pass
                    continue

def brute_force_hash(hashed_value, hash_type, use_threads):
    with open('ByteBeemWordlist.txt', 'r') as file:
        lines = [line.strip() for line in file]

    tasks = [(hashed_value, hash_type, line) for line in lines]

    if use_threads:
        with Pool(cpu_count()) as pool:
            pool.map(worker, tasks)
    else:
        with Pool(cpu_count()) as pool:
            pool.starmap(worker, tasks)

def main():
    print("Hash_brute : Themxolisi")
    print("-------------")
    print("Supported hash types:")
    print("2. MD4\n3. MD5\n4. SHA-1\n5. SHA-224\n6. SHA-256\n7. SHA-384\n8. SHA-512")
    print("9. SHA3-224\n10. SHA3-256\n11. SHA3-384\n12. SHA3-512\n13. CRC32\n14. CRC32C\n15. CRC64")
    print("16. Whirlpool\n17. Blake2s\n18. RIPEMD-128\n19. RIPEMD-160\n20. RIPEMD-256\n21. RIPEMD-320")
    print("22. Tiger192,3\n23. Skein-256\n24. Skein-512\n25. GOST94\n26. Adler32\n27. Fletcher32")
    print("28. FNV1-32\n29. FNV1a-32\n30. MurmurHash2-32\n31. MurmurHash3-32\n32. CityHash32")
    print("33. CityHash64\n34. xxHash32\n35. xxHash64\n36. Jenkins\n37. SipHash24\n38. Pearson")
    print("39. ELF\n40. Jenkins3\n41. SpookyHash32\n42. FarmHash32\n43. FarmHash64\n44. HDLC")
    print("45. bcrypt\n46. Argon2")
    print()

    

    hashed_value = input("Enter the hashed value: ")
    hash_type = input("Enter the hash type (1-46) or '0' to try all types: ")

    use_threads = False
    if hash_type == '0':
        use_threads = True

    if hash_type == '0':
        for i in range(2, 46):
            brute_force_hash(hashed_value, i, use_threads)
    else:
        hash_type = int(hash_type)
        brute_force_hash(hashed_value, hash_type, use_threads)

if __name__ == '__main__':
    main()

