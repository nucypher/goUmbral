package umbral

type UmbralPrivateKey struct {
    Params UmbralParameters
    BNKey ModBigNum
    PubKey UmbralPublicKey
}

func NewUmbralPrivateKey(bnkey ModBigNum, params UmbralParameters) (UmbralPrivateKey, error) {
    // Initializes a new UmbralPrivateKey
    pubbnkey, err := params.G.Copy()
    if err != nil {
        return UmbralPrivateKey{}, err
    }

    err = pubbnkey.Mul(bnkey)
    if err != nil {
        return UmbralPrivateKey{}, err
    }

    pubkey, err := NewUmbralPublicKey(pubbnkey, params)
    if err != nil {
        return UmbralPrivateKey{}, err
    }

    return UmbralPrivateKey{params, bnkey, pubkey}, nil
}

func GenKey(params UmbralParameters) (UmbralPrivateKey, error) {
    // Generates a new private key and returns it.
    bnkey, err := GenRandModBN(params.Curve)
    if err != nil {
        return UmbralPrivateKey{}, err
    }
    return NewUmbralPrivateKey(bnkey, params)
}

func BytesToPrivateKey(keyBytes []byte, params UmbralParameters, password []byte, scryptCost int, decoder func([]byte) []byte) (UmbralPrivateKey, error) {
    if decoder != nil {
        keyBytes = decoder(keyBytes)
    }
    if (password != nil) && (len(password) > 0) {
    }
    bnkey, err := Bytes2ModBN(keyBytes, params.Curve)
    if err != nil {
        return UmbralPrivateKey{}, err
    }
    return NewUmbralPrivateKey(bnkey, params)
}

func (m *UmbralPrivateKey) Bytes(password []byte, scryptCost, encoder func([]byte) []byte) []byte {
    privkey := m.BNKey.ToBytes()

    if (password != nil) && (len(password) > 0) {

    }

    if encoder != nil {
        privkey = encoder(privkey)
    }

    return privkey
}

type UmbralPublicKey struct {
    Params UmbralParameters
    PointKey Point
}

func NewUmbralPublicKey(pointkey Point, params UmbralParameters) (UmbralPublicKey, error) {
    return UmbralPublicKey{params, pointkey}, nil
}

func BytesToPublicKey(keyBytes []byte, params UmbralParameters, decoder func([]byte) []byte) (UmbralPrivateKey, error) {
    if decoder != nil {
        keyBytes = decoder(keyBytes)
    }
    bnkey, err := Bytes2ModBN(keyBytes, params.Curve)
    if err != nil {
        return UmbralPrivateKey{}, err
    }
    return NewUmbralPrivateKey(bnkey, params)
}

func (m *UmbralPublicKey) Bytes(encoder func([]byte) []byte, isCompressed bool) []byte {
    pointkey, err := m.PointKey.ToBytes(isCompressed)
    if err != nil {
        // returning nil on error
        return nil
    }

    if encoder != nil {
        pointkey = encoder(pointkey)
    }

    return pointkey
}
