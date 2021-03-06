/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE.rlwe_table for complete information.
 */

static unsigned int rlwe_table[52][6] = {
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x1FFFFFFF},
    {0xD6A8BD22, 0xE0C81DA0, 0x6DA13542, 0x161ABD18, 0x8806C827, 0x5CEF2C24},
    {0x14BC7408, 0x8D026C4E, 0xB3533F22, 0x4344C125, 0xCC065F20, 0x9186506B},
    {0x7D7E2A3B, 0x10AC7CEC, 0xE6217813, 0x5D62CE65, 0xBCDB43B3, 0xBAAB5F82},
    {0x6E94D801, 0x709C9299, 0x608E4D22, 0x1411F551, 0xAD23BCB1, 0xD7D9769F},
    {0x008404B7, 0x6287D827, 0x18902F20, 0x7E1526D6, 0xD6DDB5ED, 0xEA9BE2F4},
    {0x8C15F40E, 0x34CBDC11, 0x87E94674, 0xE7D2A137, 0x4919B8C9, 0xF58A9947},
    {0xBBE8C3A2, 0xD521F7EB, 0xA1EA0AAB, 0xE8A773D9, 0x2753B7B8, 0xFB511781},
    {0x31089A6A, 0xC3D9E581, 0xF716491B, 0x148CB49F, 0x928596D3, 0xFE151BD0},
    {0x842A27F6, 0x2E060C4A, 0x9ADB0049, 0x07E44D00, 0xBA9F7208, 0xFF487508},
    {0xAA887582, 0xFCEDEFCF, 0x5D4B039E, 0x1A5409BF, 0x270CFC82, 0xFFC16686},
    {0xF9FAAC20, 0x4FE22E5D, 0x0F991958, 0xFDC99BFE, 0xC159431B, 0xFFEC8AC3},
    {0x1B14FEDF, 0xA36605F8, 0x3F4AFCE0, 0xA6FCD4C1, 0xB6E92C28, 0xFFFA7DF4},
    {0x97BBC957, 0x9D1FDCFF, 0x86ED0BB5, 0x4B869C62, 0x4554B5AC, 0xFFFE94BB},
    {0x4AAD104B, 0x6B3EEBA7, 0x974D63C7, 0xEC72329E, 0x1B1CAA95, 0xFFFFAADE},
    {0x09C10760, 0x48C8DA40, 0xC1FF0A59, 0x337F6316, 0x1C6436DC, 0xFFFFEDDC},
    {0x312F35E7, 0x84480A71, 0xD6933C97, 0xD95E7B2C, 0x9DC2569A, 0xFFFFFC7C},
    {0x1513FA0F, 0x23C01DAC, 0xE72F729F, 0x8E0B132A, 0xBC337FED, 0xFFFFFF61},
    {0x70165907, 0x90C89D65, 0xAAEA5CAD, 0x05B9D725, 0xB3CF05F7, 0xFFFFFFE6},
    {0xC500EC7D, 0x692E2A94, 0x370F27A6, 0x99E8F72C, 0x53EA610E, 0xFFFFFFFC},
    {0xEAE37CC8, 0x28C2998C, 0xCAFA9AB8, 0xC6E2F0D7, 0x841943DE, 0xFFFFFFFF},
    {0xB0130256, 0xC515CF4C, 0xB4F9E4DD, 0x4745913C, 0xF12D07EC, 0xFFFFFFFF},
    {0x047D6E3A, 0x39F0ECEA, 0x42AC6544, 0xEE62D421, 0xFE63E348, 0xFFFFFFFF},
    {0xB50462D6, 0xDF11BB25, 0xC136E943, 0x064A0C6C, 0xFFD762C7, 0xFFFFFFFF},
    {0x9FD2EA0F, 0xCDBA0DD6, 0x4DB0F175, 0xC672F3A7, 0xFFFC5E37, 0xFFFFFFFF},
    {0x5F3604D9, 0xFDB966A7, 0x44723D83, 0x6ABEF8B1, 0xFFFFB48F, 0xFFFFFFFF},
    {0x600740D1, 0x3C4FECBB, 0xADD71A15, 0x697598CE, 0xFFFFFA72, 0xFFFFFFFF},
    {0x6D60E673, 0x1574CC91, 0xD99D7051, 0x12F5A30D, 0xFFFFFFA1, 0xFFFFFFFF},
    {0x9CB7321D, 0xDD3DCD1B, 0x05883572, 0x4016ED3E, 0xFFFFFFFA, 0xFFFFFFFF},
    {0x3DF79A7A, 0xB4A4E8CF, 0xAD5A73CF, 0xAF22D9AF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x96F74466, 0x91056A81, 0x905332BA, 0xFBF88681, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xBD366C04, 0x965B9ED9, 0xAF29A51F, 0xFFD16385, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x8F2D28A3, 0xF05F75D3, 0x8EA2B60C, 0xFFFE16FF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x80421EE8, 0x77E35C89, 0xC9DDC7E8, 0xFFFFEDD3, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x956F140A, 0x92783617, 0x392B6E8F, 0xFFFFFF63, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x4639AD78, 0xA536DC99, 0x3592B3D1, 0xFFFFFFFB, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x74DD9FD5, 0x8F3A8718, 0xDE04A5BB, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x0170B717, 0x310DE365, 0xFF257152, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xA422F8CC, 0x1F21A853, 0xFFFB057B, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xDB4EE2BA, 0x3CA9D5C6, 0xFFFFE5AD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x8E59869C, 0xCFD9CE95, 0xFFFFFF81, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xD955C452, 0xDB8E1F91, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xE99E08C3, 0xF78EE3A8, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x8BABDA25, 0xFFE1D785, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xE32CAB4A, 0xFFFF9E52, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x3217574F, 0xFFFFFEE1, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0x04888041, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xF8CD8A56, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFF04111, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFFFE0C5, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFFFFFC7, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
    {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
};
