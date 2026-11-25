/*
 * Random Number Generation
 * Prefers EFI_RNG_PROTOCOL (hardware RNG); falls back to a xorshift64 PRNG
 * seeded from the UEFI real-time clock on firmware without the protocol.
 */

#include "smbios.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/Rng.h>

// Local copy of EFI_RNG_PROTOCOL_GUID so we don't depend on EDK2 autogen,
// which can drop the GLOBAL_REMOVE_IF_UNREFERENCED extern under LTO.
STATIC CONST EFI_GUID mLocalRngProtocolGuid = {
    0x3152BCA5, 0xEADA, 0x4FAA,
    { 0xB1, 0x6A, 0x0E, 0x58, 0xB5, 0xBF, 0x7B, 0x2D }
};

static UINT64  gPrngState   = 0;
static BOOLEAN gPrngReady   = FALSE;

static UINT64
Xorshift64 (
    VOID
    )
{
    UINT64 x = gPrngState;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    gPrngState = x;
    return x;
}

static VOID
SeedPrng (
    VOID
    )
{
    EFI_TIME                time;
    EFI_TIME_CAPABILITIES   cap;
    UINT64                  seed = 0;

    if (gRT != NULL && gRT->GetTime != NULL &&
        !EFI_ERROR(gRT->GetTime(&time, &cap))) {
        seed  = (UINT64)time.Year        << 48;
        seed ^= (UINT64)time.Month       << 40;
        seed ^= (UINT64)time.Day         << 32;
        seed ^= (UINT64)time.Hour        << 24;
        seed ^= (UINT64)time.Minute      << 16;
        seed ^= (UINT64)time.Second      <<  8;
        seed ^= (UINT64)time.Nanosecond;
    }

    if (seed == 0) {
        seed = 0x9E3779B97F4A7C15ULL;
    }

    gPrngState = seed;
    gPrngReady = TRUE;

    // Burn a few rounds to diffuse the seed
    (VOID)Xorshift64();
    (VOID)Xorshift64();
    (VOID)Xorshift64();
}

static BOOLEAN
TryEfiRng (
    OUT UINT8  *Buffer,
    IN  UINTN   Length
    )
{
    EFI_STATUS        status;
    EFI_RNG_PROTOCOL *rng = NULL;

    if (gBS == NULL || gBS->LocateProtocol == NULL) {
        return FALSE;
    }

    status = gBS->LocateProtocol((EFI_GUID*)&mLocalRngProtocolGuid, NULL, (VOID**)&rng);
    if (EFI_ERROR(status) || rng == NULL || rng->GetRNG == NULL) {
        return FALSE;
    }

    status = rng->GetRNG(rng, NULL, Length, Buffer);
    return !EFI_ERROR(status);
}

VOID
FillRandomBytes (
    OUT UINT8  *Buffer,
    IN  UINTN   Length
    )
{
    UINTN i;

    if (Buffer == NULL || Length == 0) {
        return;
    }

    if (TryEfiRng(Buffer, Length)) {
        return;
    }

    if (!gPrngReady) {
        SeedPrng();
    }

    for (i = 0; i < Length; i += sizeof(UINT64)) {
        UINT64 v = Xorshift64();
        UINTN  n = Length - i;
        if (n > sizeof(UINT64)) {
            n = sizeof(UINT64);
        }
        CopyMem(Buffer + i, &v, n);
    }
}

INTN
RandomNumber (
    IN INTN l,
    IN INTN h
    )
{
    UINT64 v;
    INTN   range;

    if (h <= l) {
        return l;
    }

    FillRandomBytes((UINT8*)&v, sizeof(v));
    range = h - l + 1;
    return (INTN)(v % (UINT64)range) + l;
}

/**
 * Generate Random Text — strictly [A-Z0-9], the character set real SMBIOS
 * serial numbers use. Always NUL-terminated at s[len].
 */
VOID
RandomText (
    OUT CHAR8 *s,
    IN  INTN   len
    )
{
    static CONST CHAR8 alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    CONST UINTN alphabetSize = sizeof(alphabet) - 1;

    UINT8 raw[256];
    INTN  i;

    if (s == NULL || len <= 0) {
        if (s != NULL) {
            s[0] = 0;
        }
        return;
    }

    if ((UINTN)len > sizeof(raw)) {
        len = (INTN)sizeof(raw);
    }

    FillRandomBytes(raw, (UINTN)len);

    for (i = 0; i < len; i++) {
        s[i] = alphabet[raw[i] % alphabetSize];
    }
    s[len] = 0;
}
