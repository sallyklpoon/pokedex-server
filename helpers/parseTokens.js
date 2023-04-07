const parseTokens = async authToken => {
    const match = await authToken.match(/BEARER\s+([\w.-]+)\s+REFRESH\s+([\w.-]+)/);
    if (match) {
        const accessToken = match[1];
        const refreshToken = match[2];

        return { "accessToken": accessToken, "refreshToken": refreshToken };
    }
    return null;
};

const parseRefreshToken = async authToken => {
    const match = await authToken.match(/REFRESH\s+([\w.-]+)/);
    if (match) return match[1];
    return null;
};

const parseAccessToken = async authToken => {
    const match = await authToken.match(/BEARER\s+([\w.-]+)/);
    if (match) return match[1];
    return null;
};

module.exports = { 
    parseTokens,
    parseRefreshToken,
    parseAccessToken
 };
