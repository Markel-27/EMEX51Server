/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package abstractFacades;

import security.Hashing;
import entity.Employee;
import exception.CreateException;
import exception.EmailExistException;
import exception.LoginExistException;
import exception.ReadException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.persistence.EntityManager;

/**
 * Restful service for {@link Employee}. Inherits from AbstractFacade. Contains createNamedQuerys from entity 
 * <code>Employee</code> in Area51 application.
 * @author Xabier Carnero.
 */
public abstract class AbstractEmployeeFacade extends AbstractFacade<Employee> {
    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractEmployeeFacade.class.getName());
    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     * @param entityClass <code>Employee</code>.
     */
    public AbstractEmployeeFacade(Class<Employee> entityClass) {
        super(entityClass);
    }
    /**
     * Gets an {@link EntityManager} instance from one restful service from the
     * entities of the Area 51 project.
     * @return An {@link EntityManager} instance.
     */
    @Override
    protected abstract EntityManager getEntityManager();
    /**
     * Create method. Creates a new {@link Employee} instance using Hibernate. The latter executes an
     * insert operation against a MySQL database.
     * @param employee  An instance of {@link Employee} entity class.
     */
    public void createEmployee(Employee employee) throws CreateException, LoginExistException, EmailExistException {
        LOGGER.log(Level.INFO, "Metodo create de la clase AbstractBossFacade");
        try {
            employee.setPassword(Hashing.cifrarTexto(employee.getPassword()));
            super.checkLoginAndEmailNotExist(employee.getLogin(),employee.getEmail());
            super.create(employee);
        } catch (ReadException e) {
            throw new CreateException("Error when trying to create " + employee.toString());
        }
    }
    /**
     * This method finds all Area51 <code>Employee</code>.
     * @return A list containing <code>Employee</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<Employee> getAllEmployees() throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getAllEmployees de la clase AbstractEmployeeFacade");
        try {
            return getEntityManager().createNamedQuery("findAllEmployees").getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get all employees");
        }
    }
    /**
     * This method finds a <code>Employee</code> by the class attribute name.
     * @param name The class attribure name.
     * @return A list of <code>Employee</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<Employee> getEmployeesByName(String name) throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getEmployeesByName de la clase AbstractEmployeeFacade");
        try {
            return getEntityManager().createNamedQuery("findEmployeesByName")
                    .setParameter("name", name)
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get employees by name");
        }
    }
}
