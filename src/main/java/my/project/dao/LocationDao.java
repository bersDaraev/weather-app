package my.project.dao;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityTransaction;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import my.project.model.Location;
import my.project.model.User;
import my.project.util.PersistenceUtil;

import java.util.List;
import java.util.Optional;

public class LocationDao {
    private final EntityManager entityManager = PersistenceUtil.getEntityManagerFactory().createEntityManager();

    public Optional<Location> findById(Long id) {
        Location location = entityManager.find(Location.class, id);
        return Optional.ofNullable(location);
    }

    public List<Location> findByUser(User user) {
        TypedQuery<Location> query = entityManager.createQuery("SELECT l FROM Location l " +
                        "JOIN l.users u " +
                        "WHERE u.id = :userId",
                Location.class);
        query.setParameter("userId", user.getId());
        return query.getResultList();
    }

    public Optional<Location> findByCoordinates(Double latitude, Double longitude) {
        TypedQuery<Location> query = entityManager.createQuery("SELECT l FROM Location l " +
                        "WHERE l.latitude = :latitude AND " +
                        "l.longitude = :longitude",
                Location.class);
        query.setParameter("latitude", latitude);
        query.setParameter("longitude", longitude);

        // Catching RuntimeException is not good
        try {
            Location location = query.getSingleResult();
            return Optional.of(location);

        } catch (NoResultException e) {
            return Optional.empty();
        }
    }

    public void save(Location entity) {
        EntityTransaction transaction = entityManager.getTransaction();
        try {
            transaction.begin();

            entityManager.persist(entity);
            entityManager.flush();

            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
            throw new RuntimeException(e);
        }
    }

    public void delete(Location entity) {
        EntityTransaction transaction = entityManager.getTransaction();
        try {
            transaction.begin();

            entityManager.remove(entity);
            entityManager.flush();

            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
            throw new RuntimeException(e);
        }
    }

    public void update(Location entity) {
        EntityTransaction transaction = entityManager.getTransaction();
        try {
            transaction.begin();

            entityManager.merge(entity);
            entityManager.flush();

            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
            throw new RuntimeException(e);
        }
    }
}
