package renewal

type LetsEncryptConfig struct {
	Account struct {
		Email      string `yaml:"email"`
		PrivateKey string `yaml:"privateKey"`
	} `yaml:"account"`
	Directory   string `yaml:"directory"`
	Certificate string `yaml:"certificate"`
	insecure    bool
}
