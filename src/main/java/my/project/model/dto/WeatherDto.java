package my.project.model.dto;

import lombok.*;
import my.project.model.dto.enums.WeatherCondition;
import my.project.model.dto.enums.TimeOfDay;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class WeatherDto {
    private WeatherCondition weatherCondition;

    private TimeOfDay timeOfDay;

    private String description;

    private Double temperature;

    private Double temperatureFeelsLike;

    private Double temperatureMinimum;

    private Double temperatureMaximum;

    private Integer humidity;

    private Integer pressure;

    private Double windSpeed;

    private Integer windDirection;

    private Double windGust;

    private Integer cloudiness;

    private Date date;

    private Date sunrise;

    private Date sunset;
}
