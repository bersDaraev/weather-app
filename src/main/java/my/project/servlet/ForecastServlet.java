package my.project.servlet;

import jakarta.servlet.ServletException;
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
import my.project.model.Location;
import my.project.model.Session;
import my.project.model.api.ForecastApiResponse;
import my.project.model.dto.WeatherDto;
import my.project.service.ForecastService;
import my.project.service.WeatherApiService;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Slf4j
@WebServlet("/forecast")
public class ForecastServlet extends WeatherTrackerBaseServlet {
    private final SessionDao sessionDao = new SessionDao();
    private final LocationDao locationDao = new LocationDao();
    private final WeatherApiService weatherApiService = new WeatherApiService();
    private final ForecastService forecastService = new ForecastService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
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

        String locationParam = req.getParameter("locationId");

        if (locationParam == null || locationParam.isBlank()) {
            throw new InvalidParameterException("Parameter locationId is invalid");
        }

        Long locationId = Long.parseLong(locationParam);

        log.info("Finding location: " + locationId);
        Location location = locationDao.findById(locationId)
                .orElseThrow(() -> new LocationNotFoundException("Location: " + locationId + " is not found"));

        ForecastApiResponse forecastForLocation = weatherApiService.getForecastForLocation(location);

        List<WeatherDto> hourlyForecast = forecastService.getHourlyForecast(forecastForLocation);
        List<WeatherDto> dailyForecast = forecastService.getDailyForecast(forecastForLocation);

        context.setVariable("login", session.getUser().getLogin());
        context.setVariable("locationName", location.getName());
        context.setVariable("hourlyForecast", hourlyForecast);
        context.setVariable("dailyForecast", dailyForecast);

        templateEngine.process("forecast", context, resp.getWriter());
    }
}
