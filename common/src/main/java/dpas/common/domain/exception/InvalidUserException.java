package dpas.common.domain.exception;

public class InvalidUserException extends CommonDomainException {
    public InvalidUserException(String description) {
        super(description);
    }
}