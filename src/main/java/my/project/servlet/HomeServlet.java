package my.project.servlet;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import my.project.exception.CookieNotFoundException;
import my.project.exception.InvalidParameterException;
import my.project.exception.LocationNotFoundException;
import my.project.exception.SessionExpiredException;
import my.project.dao.LocationDao;
import my.project.dao.SessionDao;
import my.project.exception.api.WeatherApiCallException;
import my.project.model.Location;
import my.project.model.Session;
import my.project.model.User;
import my.project.model.api.WeatherApiResponse;
import my.project.model.api.entity.Weather;
import my.project.model.dto.WeatherDto;
import my.project.model.dto.enums.TimeOfDay;
import my.project.model.dto.enums.WeatherCondition;
import my.project.service.WeatherApiService;

import java.io.IOException;
import java.time.ZoneId;
import java.util.*;

@Slf4j
@WebServlet("")
public class HomeServlet extends WeatherTrackerBaseServlet {
    private final SessionDao sessionDao = new SessionDao();
    private final LocationDao locationDao = new LocationDao();
    private final WeatherApiService weatherApiService = new WeatherApiService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, CookieNotFoundException, SessionExpiredException, WeatherApiCallException {
        log.info("Finding cookie with session id");
        Cookie[] cookies = req.getCookies();
        Cookie cookie = findCookieByName(cookies, "sessionId")
                .orElseThrow(() -> new CookieNotFoundException("Cookie with session id is not found"));

        UUID sessionId = UUID.fromString(cookie.getValue());

        log.info("Finding session: " + sessionId);
        Session session = sessionDao.findById(sessionId)
                .orElseThrow(() -> new SessionExpiredException("Session: " + sessionId + " has expired"));

        if (isSessionExpired(session)) {
            throw new SessionExpiredException("Session: " + sessionId + " has expired");
        }

        User user = session.getUser();

        log.info("Finding locations of user: " + user.getId());
        List<Location> userLocations = locationDao.findByUser(user);

        log.info("Finding current weather for user locations");
        Map<Location, WeatherDto> locationWeatherMap = new HashMap<>();

        for (Location location : userLocations) {
            WeatherApiResponse weather = weatherApiService.getWeatherForLocation(location);
            WeatherDto weatherDto = buildWeatherDto(weather);
            locationWeatherMap.put(location, weatherDto);
        }

        context.setVariable("locationWeatherMap", locationWeatherMap);
        context.setVariable("login", user.getLogin());

        log.info("Processing home page");
        templateEngine.process("home", context, resp.getWriter());
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, CookieNotFoundException, SessionExpiredException, InvalidParameterException, LocationNotFoundException {
        log.info("Finding cookie with session id");
        Cookie[] cookies = req.getCookies();
        Cookie cookie = findCookieByName(cookies, "sessionId")
                .orElseThrow(() -> new CookieNotFoundException("Cookie with session id is not found"));

        UUID sessionId = UUID.fromString(cookie.getValue());

        log.info("Finding session: " + sessionId);
        Session session = sessionDao.findById(sessionId)
                .orElseThrow(() -> new SessionExpiredException("Session: " + sessionId + " has expired"));

        if (isSessionExpired(session)) {
            throw new SessionExpiredException("Session: " + sessionId + " has expired");
        }

        User user = session.getUser();

        String locationParam = req.getParameter("locationId");

        if (locationParam == null || locationParam.isBlank()) {
            throw new InvalidParameterException("Parameter locationId is invalid");
        }

        Long locationId = Long.parseLong(locationParam);

        log.info("Finding location: " + locationId);
        Location location = locationDao.findById(locationId)
                .orElseThrow(() -> new LocationNotFoundException("Location: " + locationId + " is not found"));

        log.info("Deleting user: " + user.getId() + " from location: " + locationId);
        List<User> users = location.getUsers();
        users.remove(user);
        location.setUsers(users);
        locationDao.update(location);

        log.info("Deleting is successful: refreshing home page");
        resp.sendRedirect(req.getContextPath());
    }

    private static WeatherDto buildWeatherDto(WeatherApiResponse weatherApiResponse) {
        Weather weather = weatherApiResponse.getWeatherList().get(0);
        return WeatherDto.builder()
                .weatherCondition(WeatherCondition.getWeatherConditionForCode(weather.getId()))
                .timeOfDay(TimeOfDay.getTimeOfDayForTime(weatherApiResponse.getDate()))
                .description(weather.getDescription())
                .temperature(weatherApiResponse.getMain().getTemperature())
                .temperatureFeelsLike(weatherApiResponse.getMain().getTemperatureFeelsLike())
                .temperatureMinimum(weatherApiResponse.getMain().getTemperatureMinimal())
                .temperatureMaximum(weatherApiResponse.getMain().getTemperatureMaximum())
                .humidity(weatherApiResponse.getMain().getHumidity())
                .pressure(weatherApiResponse.getMain().getPressure())
                .windSpeed(weatherApiResponse.getWind().getSpeed())
                .windDirection(weatherApiResponse.getWind().getDeg())
                .windGust(weatherApiResponse.getWind().getGust())
                .cloudiness(weatherApiResponse.getClouds().getCloudiness())
                .date(Date.from(weatherApiResponse.getDate().atZone(ZoneId.systemDefault()).toInstant()))
                .sunrise(Date.from(weatherApiResponse.getSys().getSunriseTime().atZone(ZoneId.systemDefault()).toInstant()))
                .sunset(Date.from(weatherApiResponse.getSys().getSunsetTime().atZone(ZoneId.systemDefault()).toInstant()))
                .build();
    }
}
