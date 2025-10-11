package org.makechtec.bearer_authentication.tools.bearer.stateless.validation;

public interface GenericValidator<T> {
    
    boolean validate(T input);
    
    String getErrorMessage();
    
}
