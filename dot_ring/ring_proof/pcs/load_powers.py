import os

HERE = os.path.dirname(__file__)

def read_srs_file():
    filename = os.path.abspath(
        os.path.join(HERE, "..", "..", "..", "tests", "ark-vrf", "bls12-381-srs-2-11-uncompressed-zcash.bin")
    )
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File {filename} not found.")

    with open(filename, "rb") as f:
        data = f.read()

    # The first 8 bytes form a little-endian uint64 that gives the number of G1 elements.
    if len(data) < 8:
        raise ValueError("File too short to contain header.")
    header = data[:8]
    g1_count = int.from_bytes(header, byteorder="little")
    # print(f"Number of G1 elements: {g1_count}")

    offset = 8
    G1_POINT_SIZE = 96  # 2 * 48-byte field elements.
    G1_points = []
    for i in range(g1_count):
        point_bytes = data[offset:offset + G1_POINT_SIZE]
        if len(point_bytes) != G1_POINT_SIZE:
            raise ValueError(f"Unexpected end-of-file when reading G1 point {i}.")
        x_bytes = point_bytes[:48]
        y_bytes = point_bytes[48:]
        x = int.from_bytes(x_bytes, byteorder="big")
        y = int.from_bytes(y_bytes, byteorder="big")
        G1_points.append((x, y))
        offset += G1_POINT_SIZE

    G2_POINT_SIZE = 192  # 2 coordinates, each with 2*48 bytes.
    G2_points = []
    # There are exactly 2 G2 points at the end of the file.
    for i in range(2):
        point_bytes = data[offset:offset + G2_POINT_SIZE]
        if len(point_bytes) != G2_POINT_SIZE:
            raise ValueError(f"Unexpected end-of-file when reading G2 point {i}.")
        x0 = int.from_bytes(point_bytes[0:48], byteorder="big")
        x1 = int.from_bytes(point_bytes[48:96], byteorder="big")
        y0 = int.from_bytes(point_bytes[96:144], byteorder="big")
        y1 = int.from_bytes(point_bytes[144:192], byteorder="big")
        G2_points.append(((x0, x1), (y0, y1)))
        offset += G2_POINT_SIZE

    return G1_points, G2_points

g1_points,g2_point_unused= read_srs_file()


g2_points=[((352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160,3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758)
            ,(1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905,
              927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582))
    ,((186544079744757791750913777923182116923406997981176124505869835669370349308168084101869919858020293159217147453183,2680951345815209329447762511030627858997446358927866220189443219836425021933771668894483091748402109907600527683136)
      ,(2902268288386460594512721059125470579172313681349425350948444194000638363935297586336373516015117406788334505343385,1813420068648567014729235095042931383392721750833188405957278380281750025472382039431377469634297470981522036543739))]

# assert G1 in g1_points, "G1 powers are invalid"
# assert G2 in g2_points, "G2 powers are invalid"
