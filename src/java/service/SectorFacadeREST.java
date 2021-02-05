/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package service;

import abstractFacades.AbstractFacade;
import abstractFacades.AbstractSectorFacade;
import entity.Sector;
import entity.SectorType;
import exception.CreateException;
import exception.DeleteException;
import exception.ReadException;
import exception.SectorNotExistException;
import exception.UpdateException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * RESTful service for Sector entity. Includes CRUD operations.
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde
 * @since 04/12/2020
 * @version 1.0
 */
@Stateless
@Path("sector")
public class SectorFacadeREST extends AbstractSectorFacade {
    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(SectorFacadeREST.class.getName());
    /**
     * Injects an {@link EntityManager} instance.
     */
    @PersistenceContext(unitName = "EMEX51CRUDServerPU")
    private EntityManager em;
    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     */
    public SectorFacadeREST() {
        super(Sector.class);
    }
    /**
     * Create (Insert) operation after receiving a Post HTTP order.
     * @param entity The sector object in xml format.
     */
    @POST
    @Override
    @Consumes({MediaType.APPLICATION_XML})
    public void create(Sector entity) {
        LOGGER.log(Level.INFO, "Metodo create de la clase SectorFacade");
        try {
            super.create(entity);
        } catch (CreateException ex) {
            Logger.getLogger(ArmyFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new ForbiddenException(ex);
        }
    }
    /**
     * Edit (Update) operation after receiving a Delete HTTP order.
     * @param entity The sector object in xml format.
     */
    @PUT
    @Consumes({MediaType.APPLICATION_XML})
    @Override
    public void edit(Sector entity) {
        LOGGER.log(Level.INFO, "Metodo edit de la clase SectorFacade");
        try {
            super.edit(entity);
        } catch (UpdateException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }
    /**
     * Remove (Delete) operation after receiving a Delete HTTP order.
     * @param id An id value of a sector.
     */
    @DELETE
    @Path("{id}")
    public void remove(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo remove de la clase SectorFacade");
        try {
            super.deleteSector(super.find(id));
        } catch (ReadException | DeleteException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }
    /**
     * Find (Select) operation after receiving a Get HTTP order.
     * @param id An id value of a sector.
     * @return A Sector object in xml format.
     */
    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_XML})
    public Sector find(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo find de la clase SectorFacade");
        try {
            return super.find(id);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }
    /**
     * Gets all the <code>Sector</code> of the Area51.
     * @return A list of {@link Sector}
     */
    @GET
    @Path("all")
    @Produces({MediaType.APPLICATION_XML})
    public List<Sector> findAllSectors() {
        LOGGER.log(Level.INFO, "Metodo findAll de la clase SectorFacade");
        try {
            return super.getAllSectors();
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new NotFoundException(ex.getMessage());
        }
    }
    /**
     * Gets all the <code>Sector</code> of the Area51 whose name equals the String passed as parameter.
     * @param name A String. 
     * @return A list of {@link Sector}
     */
    @GET
    @Path("name/{name}")
    @Produces({MediaType.APPLICATION_XML})
    public Sector findSectorsByName(@PathParam("name") String name) {
        LOGGER.log(Level.INFO, "Metodo find by name de la clase SectorFacade");
        try {
            return super.getSectorsByName(name);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        } catch (SectorNotExistException ex) {
            Logger.getLogger(SectorFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new NotFoundException();
        }
    }
    /**
     * Gets all the <code>Sector</code> of the Area51 whose name equals the String passed as parameter.
     * @param name A String. 
     * @return A list of {@link Sector}
     */
    @GET
    @Path("type/{type}")
    @Produces({MediaType.APPLICATION_XML})
    public List<Sector> findSectorsByType(@PathParam("type") SectorType type) {
        LOGGER.log(Level.INFO, "Metodo find by type de la clase SectorFacade");
        try {
            return super.getSectorsByType(type);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Gets an {@link EntityManager} instance.
     *
     * @return An {@link EntityManager} instance.
     */
    @Override
    protected EntityManager getEntityManager() {
        LOGGER.log(Level.INFO, "Metodo getEntityManager de la clase SectorFacade");
        return em;
    }
}