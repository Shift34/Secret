import datetime


def get_guessed_gamma(ciphertext):
    secutiTag = ['СЕКРЕТНО', 'СОВЕРШЕННО СЕКРЕТНО', 'ДЛЯ СЛУЖЕБНОГО ПОЛЬЗОВАНИЯ']
    dataTypeValue = ['txt', 'pdf', 'jpg', 'webm', 'djvu', 'm4a', 'bmp']
    gamma_fragment = []
    polynom = []

    for i in secutiTag:
        for j in dataTypeValue:
            known_fragment = ('{"securityTag":"' + i + '","content":{"dataType":"' + j + '","data":"').encode("UTF8")
            fragment = []
            for l in range(0, len(known_fragment)):
                fragment.append(known_fragment[l] ^ ciphertext[l])
            gamma_fragment.append(fragment)
            polynom.append(berlekamp_massey(fragment))

    pravlil_polinom = []
    pravil_gamma = []
    for i, y in zip(gamma_fragment, polynom):
        if len(y) * 2 < len(i):
            [pravlil_polinom.append(l) for l in y]
            [pravil_gamma.append(l) for l in i]

    gamma = printNextSeq(pravil_gamma, len(pravlil_polinom) - 1, pravlil_polinom,
                         len(ciphertext) - len(pravlil_polinom) + 1)

    gamma_okon = pravil_gamma[:len(pravlil_polinom) - 1] + gamma[:]
    return gamma_okon


def printNextSeq(sourceSeq, L, lfsr, count):
    registr = [0] * L
    gamma = []
    for i in range(L):
        registr[i] = sourceSeq[L - i - 1]
    for i in range(count):
        next_s = 0
        for j in range(L):
            next_s ^= gf_mult(lfsr[j + 1], registr[j])

        for j in range(L - 1, 0, -1):
            registr[j] = registr[j - 1]
        registr[0] = next_s
        gamma.append(next_s)
    return gamma


def berlekamp_massey(sequence):
    n = len(sequence)
    C = [1] + [0] * n  # Текущий многочлен
    B = [1] + [0] * n  # Предыдущий многочлен
    L = 0  # Текущая длинна
    m = 1
    b = 1

    for i in range(n):
        # Вычисляем несогласованность
        d = sequence[i]
        for j in range(1, L + 1):
            d ^= gf_mult(C[j], sequence[i - j])

        if d != 0:
            T = C[:]
            factor = gf_mult(d, gf_inverse(b))
            for j in range(m, n + 1):
                if j < len(B):
                    C[j] ^= gf_mult(factor, B[j - m])
            if 2 * L <= i:
                L = i + 1 - L
                B = T
                b = d
                m = 0

        m += 1

    # Удаляем ведущие нули
    while len(C) > 1 and C[-1] == 0:
        C.pop()

    return C[:L + 1]


def gf_mult(x, y, p=0x11d):
    res = 0
    while y > 0:
        if y & 1:
            res ^= x
        x <<= 1
        if x & 0x100:
            x ^= p
        y >>= 1
    return res


def gf_inverse(x, p=0x11d):
    for i in range(1, 256):
        if gf_mult(x, i, p) == 1:
            return i


def extract_field(data_str, field_name):
    index = data_str.find(field_name) + len(field_name)
    res = ""
    current_ch = data_str[index]
    while current_ch != "\"":
        res += current_ch
        index += 1
        current_ch = data_str[index]
    return res


# test = [2, 39, 3, 139, 28, 149, 174, 56, 29]
# polynom = berlekamp_massey(test)
# # polynom = [1, 1, 1, 0]
# print(printNextSeq(test, len(polynom) - 1, polynom, 20), sep=',')

start = datetime.datetime.now()

with open("1.encrypted", "rb") as file:
    bytes_from_file = file.read()

    gamma = get_guessed_gamma(bytes_from_file)

    plaintext = bytes([x ^ y for x, y in zip(bytes_from_file, gamma)]).decode("UTF8")
    print(plaintext[0:200])
    mask = extract_field(plaintext, '"mask":"').encode("UTF8")
    data = bytes.fromhex(extract_field(plaintext, '"data":"'))

    print(mask)
    print(data[0:100])

    decrypted_data = []
    for i in range(0, len(data)):
        decrypted_data.append(data[i] ^ mask[i % len(mask)])
    print(bytes(decrypted_data[0:100]).hex())
    with open("decrypted_data.webm", "wb") as res_file:
        res_file.write(bytes(decrypted_data))
    finish = datetime.datetime.now()
    print((finish - start).seconds)
