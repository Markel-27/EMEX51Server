/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package abstractFacades;

import entity.Boss;
import entity.Employee;
import exception.ReadException;
import java.util.List;
import javax.persistence.EntityManager;
import entity.User;
import exception.EmailNotExistException;
import exception.IncorrectPasswordException;
import exception.LoginNotExistException;
import exception.PasswordDontMatchException;
import exception.UpdateException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import security.Hashing;
import security.MailService;
import security.PasswordOptions;
import security.PrivateKeyServer;

/**
 * Restful service for <code>User</code>. Inherits from AbstractFacade. Contains
 * createNamadQuerys from entity User in Area51 application.
 *
 * @author Xabier Carnero.
 */
public abstract class AbstractUserFacade extends AbstractFacade<User> {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractUserFacade.class.getName());

    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     *
     * @param entityClass <code>User</code>.
     */
    public AbstractUserFacade(Class<User> entityClass) {
        super(entityClass);
    }

    /**
     * Gets an {@link EntityManager} instance from one restful service from the
     * entities of the Area 51 project.
     *
     * @return An {@link EntityManager} instance.
     */
    @Override
    protected abstract EntityManager getEntityManager();

    /**
     * This method finds all Area51 users.
     *
     * @return A list containing the users.
     * @throws ReadException Thrown when any error produced during the read
     * operation.
     */
    public List<User> getAllUsers() throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getAllUsers de la clase AbstractUserFacade");
        try {
            return getEntityManager().createNamedQuery("findAllUsers").getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get all Users");
        }
    }

    /**
     * This method finds a <code>User</code> in the database to check if the
     * login is already recorded in the database.
     *
     * @param login A String.
     * @return An User instance.
     * @throws ReadException Thrown when any error produced during the read
     * operation.
     * @throws exception.LoginNotExistException
     */
    public User getUserByLogin(String login) throws ReadException, LoginNotExistException {
        LOGGER.log(Level.INFO, "Metodo getUserByLogin de la clase AbstractUserFacade");
        
        User user = new User();
            List<User> users = getAllUsers();
            for (User u: users) {
                if (u.getLogin().compareToIgnoreCase(login) == 0) {
                    if (u instanceof Boss){
                        user.setLogin("Boss");
                    } else if(u instanceof Employee){
                        user.setLogin("Employee");
                    }
                    return user;
                }
            }
            throw new LoginNotExistException();
    }

    public User login(String login, String password) throws IncorrectPasswordException, LoginNotExistException, ReadException {
        LOGGER.log(Level.INFO, "Login method from AbstractUSerFacade");
        password = Hashing.cifrarTexto(Arrays.toString(PrivateKeyServer.descifrarTexto(password)));
        List<User> users = getAllUsers();
        for (User u: users) {
            if (u.getLogin().equals(login)) {
                if (u.getPassword().equals(password)) {
                    return u;
                } else {
                    throw new IncorrectPasswordException();
                }
            }
        }
        throw new LoginNotExistException();
    }

    public void sendEmail(String email) throws ReadException, UpdateException, EmailNotExistException {
        Boolean exist = false;
        List<User> users = getAllUsers();
        for (User u : users) {
            if (u.getEmail().compareToIgnoreCase(email) == 0) {
                exist = true;
                String tempPass = makePassword();
                MailService.sendRecoveryMail(email, tempPass);
                u.setPassword(Hashing.cifrarTexto(tempPass));
                super.edit(u);
            }
        }
        
        if(!exist)
            throw new EmailNotExistException();
    }

    public void newPassword(String email, String tempPass, String newPass) throws ReadException, UpdateException, PasswordDontMatchException {
        List<User> users = getAllUsers();
        for (User u : users) {
            if (u.getEmail().compareToIgnoreCase(email) == 0) {
                if (u.getPassword().compareToIgnoreCase(Hashing.cifrarTexto(tempPass)) == 0) {
                    newPass = Arrays.toString(PrivateKeyServer.descifrarTexto(newPass));
                    u.setPassword(Hashing.cifrarTexto(newPass));
                    super.edit(u);
                } else {
                    throw new PasswordDontMatchException();
                }
            }
        }
    }

    private String makePassword() {
        String newPassword = PasswordOptions.getPassword(PasswordOptions.MINUSCULAS
                + PasswordOptions.MAYUSCULAS
                + PasswordOptions.ESPECIALES, 10);
        return newPassword;
    }
}
