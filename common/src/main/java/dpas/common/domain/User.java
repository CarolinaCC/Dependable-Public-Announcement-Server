package dpas.common.domain;

import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;

import java.security.PublicKey;

public class User {

    private String _username;
    private PublicKey _publicKey;
    private UserBoard _userBoard;

    public User(String username, PublicKey publicKey) throws NullPublicKeyException, NullUsernameException, NullUserException {
        checkArguments(username, publicKey);
        this._username = username;
        this._publicKey = publicKey;
        this._userBoard = new UserBoard(this);
    }

    public void checkArguments(String username, PublicKey publicKey) throws NullPublicKeyException, NullUsernameException {
        if (username == null || username.isBlank()) {
            throw new NullUsernameException();
        }

        if (publicKey == null) {
            throw new NullPublicKeyException();
        }
    }

    public String getUsername() {
        return _username;
    }

    public PublicKey getPublicKey() {
        return _publicKey;
    }

    public UserBoard getUserBoard() {
        return _userBoard;
    }

    //Comparing two users
    public boolean equals(User other) {
        return this._publicKey.equals(other._publicKey) && this._username.equals(other._username);
    }

}
