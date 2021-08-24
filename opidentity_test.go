package opidentity

import (
	"testing"
	"time"
)

/*
func TestDecodeIdentityToken(t *testing.T) {
	encryptionKey, err := NewPrivateKeyFromFile("sandbox-sp-encryption-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	IDToken := "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJNZllHdU9OV1FaYWJ3d3BoMDJ6SkVxT1FJUE9WMVBoRXNjZ0hjaDBRcUQwIn0.CnlpvMesDnsrzlAaGEWihiFvrn8l-w7lYQSzrW2QtGU1vzrlpsZYRylkvcRaVJRAhtL5uQKsTHyJ4p_okgwp0Xuv2hFYHKT4-LUwzGDHLiGjkQyNe5pk9lLSwACC67uHu1Pc8mK37HKgMvpgySdNKAa2YpZUKoenu9SBO9-GmwcskK5wfvEj9-DA7RjvRsxv2w1CQSUpmUcu4eDR2996hfhgHfveDwreyJCtPEHYdp0vY5cWNUTzVt3WKRU-guk0So4TxEsqngLqoTbTflBhMI67bekB9V4dZxaSRZMf61G-K296Ae8xjM450lW7EsQV3M8G4YI_mB7tyvvP4U2U9Q.-G-l3kUz0EtB6hvzszT9KQ.x9dz45b5NSy_uWCmk1WDT3Ro71iMc0FF1NhCdDDVkTICooGmDHQGneD2MGL6iek5bXQe56L0sNNYI_dl90Bs9uHMVepx9B5vO9KlcdkX-Je-1yRCsKz-WkX2_PgtVW9uXjIZPkPqN91VKrGFZz9djdTis7Y8FkDI1sKfW4v8ujYV8slh373ZUKgMMlvEtN4cpYR4CXyXPpjjq6lmdsTTBWD61m2uFwLC8iatUo5QJu85CuJdarlW0W-nh05ECkPTatYQ-2Ree9jHm2U5YFemKkpww77BbgzePH1PUIUe6sc2vBQMpoQjeNdHqWguJDeUlwgS8qQn_5UKuk_9o39e3QKLClmUVX84_A5opId-Y6i0L0b9NEGlC4SXpyQVcXU3FLAvR1ub7ztKGG9w73PIJTme4kUclTlD8zm3sDhxT0SbqtDe1TpcjbWbRzx4C3ajio8h-ND9LzG6ViL6OWV4CRfh5FlObfKzkd8X8RpI3RR_7W1CJRHXy2Bkd5Jz4jYBdgX_Nri9o5amO781McYS3D9HvB7rMbbKPmS46UenaeBRmFrR6QP0avZ4j3PTErLFCowxJT9D1LRPMFuxqhQcbtf_oz3iWmDf9PuRwrUaWZzQRFnCBdZ51DuEl7sKEEohNsYM5L6i5j7NC1eYMf6eaEM2zR6WHnaz-fI_mnM2cjIln1lLk-IwgdLNHGoiydGLHMjICONcfe5dEBMyDCHklh0RMpyUDjQa69XVO-wiHJIr8MuKW-dYGKJkZnIZt7XhT4OB7tsTZ7vuxe2Q3rxM5H9nF_22vNfPYBwOQu4NS3nD4KYzz5aiGc58GQ6O_FhohD9IMtP3D74Bav6tm9NPcTUYNhhtaZk7l87HjyS3nDXAHOeFIY7wbHj_I-dfAkQIencezJlBZQMNVaXlqqyhvKQwxNR2hcZ_ijB_4sisJCaCynlKAKLaK0UO3LhRoV1CqrMiaIw4CY31LHog1zeU9Z97yDNJKOQ3aPatEi7bXLMTwuA565KDfZ8DtizAgcBQ2WEXYRVqiAtPYcetP6AyTF6K_ygjGhbmPmjgL7hU3IyHvrZIkLdc6-apgARWxsFWVcGz_LbDp785isxTGAQxsQ._vS2vXIm1eLIcWNNcgCKNw"
	_, err = DecodeIdentityToken(IDToken, encryptionKey)
	if err != nil {
		t.Error(err)
	}
}
*/
func TestIdentityExpiration(t *testing.T) {
	i := Identity{Expiration: time.Now().Unix()}
	time.Sleep(1 * time.Second)
	if err := i.IsValid(); err == nil {
		t.Error("identity should be expired")
	}
}

func TestNewSignature(t *testing.T) {
	key, err := NewPrivateKeyFromFile("example/httpd/sandbox-sp-signing-key.pem")
	if err != nil {
		t.Error(err)
	}
	want := "eyJhbGciOiJSUzI1NiJ9.VEVTVA.klvw9HBctNBRHYjJF-N_FPbY2vGzS9IqF7rsuUqr88RHydhdbUgtnQdImEYowe2aWflvfzoXi05i00Q90nssPYFBSkya2np3iXywm5AmLHOQtGDXSAGPmHs4MkXRlW2mQ0s1MT3NJKZIjPgvMwS1sdwdkIAv3xHhk5fZL-4594CgyIGTvIFHEZPlpkM9_L7JCIRTraq7zv8F9wsDs6g_dKdRTcfJDjNVzYep67Nnhusbt-Npe583csCn9ow9M3CLYqSArgjcMkr8e6pDlA0o6mzHG7KDpa4EYNfP-twQTrcl-orGigHDglKGk0VEVv5D3CGAsYZsXr-uhR4sr-4OeA"
	got, err := NewSignature([]byte("TEST"), key)
	if err != nil {
		t.Error(err)
	}
	if want != got {
		t.Errorf("signature mismatch want '%s' got '%s'", want, got)
	}
}
