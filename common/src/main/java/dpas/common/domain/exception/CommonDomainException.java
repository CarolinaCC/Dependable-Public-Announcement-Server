package dpas.common.domain.exception;

public abstract class CommonDomainException extends Exception {

    public CommonDomainException(String description) {
        super(description);
    }
}
