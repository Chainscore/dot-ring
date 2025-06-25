from dot_ring.ring_proof.constants import SIZE


def is_power_of_two(n):
    # is n==2**x
    return n and (n & (n - 1)) == 0


def modinv(a, p):
    #find x such that a*x= 1 mod p
    return pow(a, -1, p)


#In general fft
def fft(a, omega, p): #coeffs to evaluation points
    n = len(a)
    # target_len = n
    # N = next_power_of_two(target_len)
    # omega = 49307615728544765012166121802278658070711169839041683575071795236746050763237
    # # Scale root of unity if needed
    # root_order = N
    # omega= pow(omega, (2048 // root_order), p)
    if n == 1:
        return a
    a_even = fft(a[::2], pow(omega, 2, p), p)
    a_odd = fft(a[1::2], pow(omega, 2, p), p)
    y = [0] * n
    x = 1
    for i in range(n // 2):
        t = (x * a_odd[i]) % p
        y[i] = (a_even[i] + t) % p
        y[i + n // 2] = (a_even[i] - t) % p
        x = (x * omega) % p
    return y



def poly_interpolate_fft(a, omega, p): # funcs like inverse_fft from evals to poly coeffs
    n = len(a)
    N= next_power_of_two(n)
    omega_2048=49307615728544765012166121802278658070711169839041683575071795236746050763237
    if N>SIZE:
        omega = pow(omega_2048, (2048 // N), p)

    omega_inv = modinv(omega, p)
    y = fft(a, omega_inv, p)
    n_inv = modinv(n, p)
    return [(val * n_inv) % p for val in y]


import math
def next_power_of_two(n):
    return 1 << (n - 1).bit_length()


def poly_mul_fft(a, b, prime):
    target_len = 2048
    N = next_power_of_two(target_len)
    omega=49307615728544765012166121802278658070711169839041683575071795236746050763237
    # Scale root of unity if needed
    root_order = N
    omega_N = pow(omega, (2048 // root_order), prime)  # If omega is for 2048, scale down

    # Pad inputs
    A = a + [0] * (N - len(a))
    B = b + [0] * (N - len(b))

    # FFT both
    A_eval = fft(A, omega_N, prime)
    B_eval = fft(B, omega_N, prime)

    # Multiply evaluations
    C_eval = [(ae * be) % prime for ae, be in zip(A_eval, B_eval)]

    # Inverse FFT to get result
    C = poly_interpolate_fft(C_eval, omega_N, prime)
    # Trim to true degree
    return C[:target_len]

