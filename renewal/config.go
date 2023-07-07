package renewal

type LetsEncryptConfig struct {
	Account     LetsEncryptAccount `yaml:"account"`
	Directory   string             `yaml:"directory"`
	Certificate string             `yaml:"certificate"`
	insecure    bool
}

type LetsEncryptAccount struct {
	Email      string `yaml:"email"`
	PrivateKey string `yaml:"key"`
}
