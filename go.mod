module gonc

go 1.16

require (
	github.com/dddpaul/gonc v0.0.0-20160922094557-01630e0d68a7
	github.com/stretchr/testify v1.7.0
	utils/tcp v0.0.0-00010101000000-000000000000
)

replace utils/tcp => ../gonc/tcp
