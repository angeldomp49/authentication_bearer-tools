package org.makechtec.bearer_authentication.tools.bearer.stateless.validation;


import java.util.Arrays;

public class GenericValidationApplier<T> {
    
    private GenericValidator<T> invalidator;
    
    public boolean applyAllValidations(T input, GenericValidator<T>... validators){
        var invalidator =
            Arrays.stream(validators)
                    .sequential()
                    .filter(genericStringValidator -> 
                            !genericStringValidator.validate(input))
                    .findAny();
        
        if(invalidator.isPresent()){
            this.invalidator = invalidator.get();
            return false;
        }
        
        return true;
        
    }
    
    public GenericValidator<T> getInvalidator() {
        return invalidator;
    }
    
}
