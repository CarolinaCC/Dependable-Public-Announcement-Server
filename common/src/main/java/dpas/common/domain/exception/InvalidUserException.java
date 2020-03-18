package dpas.common.domain.exception;

public class InvalidUserException extends Exception {
    public InvalidUserException(String description) {
        super(description);
    }
}